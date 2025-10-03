/* eslint-disable no-console */
const axios = require('axios');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

/**
 * Convert IPv4 string to unsigned 32-bit integer
 * @param {string} ip
 * @returns {number}
 */
function ipToInt(ip) {
  const parts = ip.split('.').map((x) => parseInt(x, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  // Use >>> 0 to keep unsigned
  return (((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0)) >>> 0;
}

/**
 * Check if IPv4 belongs to CIDR
 * @param {string} ip
 * @param {string} cidr e.g. "217.16.16.0/21"
 * @returns {boolean}
 */
function ipInCidr(ip, cidr) {
  const [base, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  if (Number.isNaN(bits) || bits < 0 || bits > 32) {
    throw new Error(`Invalid CIDR: ${cidr}`);
  }
  const ipInt = ipToInt(ip);
  const baseInt = ipToInt(base);
  const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
  const network = baseInt & mask;
  return (ipInt & mask) === network;
}

/**
 * Sleep helper
 * @param {number} ms
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Derive Nova base URL.
 * Priority: NOVA_BASE_URL env/CLI -> fallback to default public endpoint.
 * @param {string | undefined} override
 * @returns {string} e.g. "https://infra.mail.ru:8774"
 */
function deriveNovaBaseUrl(override) {
  if (override) return override.replace(/\/+$/, '');
  return 'https://infra.mail.ru:8774';
}

/**
 * Create axios instance for Nova API
 */
function makeNovaClient({ token, projectId, novaBaseUrl, microversion = '2.1' }) {
  if (!token) {
    throw new Error('X-Auth-Token is required (set X_AUTH_TOKEN env or --token CLI)');
  }
  if (!projectId) {
    throw new Error('OS_PROJECT_ID is required (set OS_PROJECT_ID env or --project-id CLI)');
  }
  if (!novaBaseUrl) {
    throw new Error('Nova base URL is required');
  }
  const baseURL = `${novaBaseUrl.replace(/\/+$/, '')}/v2.1/${projectId}`;
  const client = axios.create({
    baseURL,
    headers: {
      'X-Auth-Token': token,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-OpenStack-Nova-API-Version': microversion,
    },
    timeout: 30000,
    validateStatus: (s) => s >= 200 && s < 500,
  });
  return client;
}

/**
 * Derive Glance base URL from override or default public endpoint
 */
function deriveGlanceBaseUrl(override) {
  if (override) return override.replace(/\/+$/, '');
  return 'https://infra.mail.ru:9292';
}

/**
 * Derive Neutron base URL from override or default public endpoint
 */
function deriveNeutronBaseUrl(override) {
  if (override) return override.replace(/\/+$/, '');
  return 'https://infra.mail.ru:9696';
}

/**
 * Derive Cinder base URL from override or default public endpoint
 */
function deriveCinderBaseUrl(override) {
  if (override) return override.replace(/\/+$/, '');
  return 'https://infra.mail.ru:8776';
}

/**
 * Create axios instance for Cinder API (v3)
 */
function makeCinderClient({ token, cinderBaseUrl, projectId }) {
  if (!token) throw new Error('X-Auth-Token is required for Cinder');
  if (!cinderBaseUrl) throw new Error('Cinder base URL is required');
  if (!projectId) throw new Error('OS_PROJECT_ID is required for Cinder');
  const baseURL = `${cinderBaseUrl.replace(/\/+$/, '')}/v3/${projectId}`;
  return axios.create({
    baseURL,
    headers: {
      'X-Auth-Token': token,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    timeout: 30000,
    validateStatus: (s) => s >= 200 && s < 500,
  });
}

/**
 * List Cinder volume types
 */
async function listVolumeTypes(cinderClient) {
  const res = await cinderClient.get('/types', { params: { is_public: true } });
  if (res.status >= 400) throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.data)}`);
  const types = (res.data && (res.data.volume_types || res.data.types || [])) || [];
  return types.map((t) => ({ id: t.id, name: t.name }));
}

/**
 * Create axios instance for Glance API
 */
function makeGlanceClient({ token, glanceBaseUrl }) {
  if (!token) throw new Error('X-Auth-Token is required for Glance');
  if (!glanceBaseUrl) throw new Error('Glance base URL is required');
  const baseURL = `${glanceBaseUrl.replace(/\/+$/, '')}`;
  return axios.create({
    baseURL,
    headers: {
      'X-Auth-Token': token,
      Accept: 'application/json',
    },
    timeout: 30000,
    validateStatus: (s) => s >= 200 && s < 500,
  });
}

/**
 * Create axios instance for Neutron API
 */
function makeNeutronClient({ token, neutronBaseUrl }) {
  if (!token) throw new Error('X-Auth-Token is required for Neutron');
  if (!neutronBaseUrl) throw new Error('Neutron base URL is required');
  const baseURL = `${neutronBaseUrl.replace(/\/+$/, '')}`;
  return axios.create({
    baseURL,
    headers: {
      'X-Auth-Token': token,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    timeout: 30000,
    validateStatus: (s) => s >= 200 && s < 500,
  });
}

/**
 * List available flavors with details
 */
async function listFlavors(novaClient) {
  const res = await novaClient.get('/flavors/detail');
  if (res.status >= 400) throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.data)}`);
  const flavors = (res.data && res.data.flavors) || [];
  return flavors.map((f) => ({
    id: f.id,
    name: f.name,
    vcpus: f.vcpus,
    ram: f.ram,
    disk: f.disk,
  }));
}

/**
 * List active images from Glance (fetch all pages)
 */
async function listImages(glanceClient) {
  const all = [];
  let url = '/v2/images';
  let params = { status: 'active', sort: 'name:asc', limit: 100 };

  // Iterate through all pages using "next" marker/link
  // Glance v2 typically returns either "next" or links[{ rel: 'next', href }]
  /* eslint-disable no-constant-condition */
  while (true) {
    const res = await glanceClient.get(url, params ? { params } : undefined);
    if (res.status >= 400) throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.data)}`);

    const images = (res.data && res.data.images) || [];
    for (let i = 0; i < images.length; i += 1) {
      all.push(images[i]);
    }

    // Determine next page
    let next = res.data && res.data.next;
    if (!next) {
      const links = (res.data && res.data.links) || [];
      if (Array.isArray(links)) {
        const ln = links.find((l) => l && l.rel === 'next');
        if (ln && ln.href) next = ln.href;
      }
    }

    if (!next) break;
    url = next;         // can be absolute or relative; axios handles both
    params = undefined; // next already contains full query string
  }

  return all.map((img) => ({
    id: img.id,
    name: img.name,
    size: img.size,
    visibility: img.visibility,
  }));
}

/**
 * List networks from Neutron (project + external shared)
 */
async function listNetworks(neutronClient, projectId) {
  const requests = [
    neutronClient.get('/v2.0/networks', { params: projectId ? { project_id: projectId } : undefined }),
    neutronClient.get('/v2.0/networks', { params: { 'router:external': true } }),
  ];

  const seen = new Set();
  const collected = [];

  const responses = await Promise.all(requests);
  for (const res of responses) {
    if (res.status >= 400) throw new Error(`HTTP ${res.status}: ${JSON.stringify(res.data)}`);
    const networks = (res.data && res.data.networks) || [];
    for (const n of networks) {
      if (n && n.id && !seen.has(n.id)) {
        seen.add(n.id);
        collected.push(n);
      }
    }
  }

  return collected.map((n) => ({
    id: n.id,
    name: n.name,
    project_id: n.project_id || n.tenant_id,
    'router:external': n['router:external'],
    shared: n.shared,
    status: n.status,
  }));
}

/**
 * Build server creation payload
 */
function buildCreateServerBody(params) {
  const {
    name,
    imageId,
    flavorId,
    networkId,
    keyName,
    securityGroups,
    userDataBase64,
    availabilityZone,
    volumeSizeGb,
    volumeType,
  } = params;

  if (!name) throw new Error('Server name is required');
  if (!imageId) throw new Error('IMAGE_ID is required');
  if (!flavorId) throw new Error('FLAVOR_ID is required');

  const server = {
    name,
    flavorRef: flavorId,
  };

  // If volume size specified, boot from volume of given size, otherwise use imageRef
  if (typeof volumeSizeGb === 'number' && !Number.isNaN(volumeSizeGb) && volumeSizeGb > 0) {
    server.block_device_mapping_v2 = [{
      boot_index: 0,
      uuid: imageId,
      source_type: 'image',
      destination_type: 'volume',
      volume_size: Math.floor(volumeSizeGb),
      delete_on_termination: true,
      ...(volumeType ? { volume_type: volumeType } : {}),
    }];
  } else {
    server.imageRef = imageId;
  }

  if (networkId) {
    server.networks = [{ uuid: networkId }];
  }
  if (keyName) {
    server.key_name = keyName;
  }
  if (securityGroups && securityGroups.length > 0) {
    server.security_groups = securityGroups.map((g) => ({ name: g }));
  }
  if (userDataBase64) {
    server.user_data = userDataBase64;
  }
  if (availabilityZone) {
    server.availability_zone = availabilityZone;
  }

  return { server };
}

/**
 * Extract IPv4 list from Nova server object
 */
function getIPv4sFromServer(server) {
  const ips = [];
  // accessIPv4 (legacy)
  if (server.accessIPv4) {
    ips.push(server.accessIPv4);
  }
  // addresses: { netName: [ { addr, version }, ... ] }
  if (server.addresses && typeof server.addresses === 'object') {
    Object.keys(server.addresses).forEach((net) => {
      const arr = server.addresses[net];
      if (Array.isArray(arr)) {
        arr.forEach((a) => {
          if (a && a.addr && a.version === 4) {
            ips.push(a.addr);
          }
        });
      }
    });
  }
  // unique
  return Array.from(new Set(ips.filter(Boolean)));
}

/**
 * Wait for server to become ACTIVE (or ERROR)
 */
async function waitForActive(nova, serverId, pollIntervalMs, maxWaitMs) {
  const started = Date.now();
  let lastStatus = '';
  while (true) {
    const res = await nova.get(`/servers/${serverId}`);
    if (res.status === 404) {
      throw new Error(`Server ${serverId} not found while polling`);
    }
    if (res.status >= 400) {
      throw new Error(`Failed to poll server ${serverId}, status ${res.status}: ${res.data && JSON.stringify(res.data)}`);
    }
    const server = res.data && res.data.server;
    lastStatus = (server && server.status) || '';
    if (lastStatus === 'ACTIVE') {
      return server;
    }
    if (lastStatus === 'ERROR') {
      throw new Error(`Server ${serverId} entered ERROR status`);
    }
    if (Date.now() - started > maxWaitMs) {
      throw new Error(`Timeout waiting for server ${serverId} to become ACTIVE (last status: ${lastStatus})`);
    }
    await sleep(pollIntervalMs);
  }
}

/**
 * Delete server and optionally wait for deletion
 */
async function deleteServer(nova, serverId, wait = true, pollIntervalMs = 3000, maxWaitMs = 120000) {
  const res = await nova.delete(`/servers/${serverId}`);
  if (res.status >= 400) {
    console.warn(`Delete server ${serverId} returned ${res.status}: ${res.data && JSON.stringify(res.data)}`);
  }
  if (!wait) return;
  const started = Date.now();
  while (true) {
    const r = await nova.get(`/servers/${serverId}`);
    if (r.status === 404) {
      return;
    }
    if (Date.now() - started > maxWaitMs) {
      console.warn(`Timeout waiting for server ${serverId} deletion`);
      return;
    }
    await sleep(pollIntervalMs);
  }
}

/**
 * Build detailed auth error hint for 401/403
 */
function describeAuthError(status, novaBaseUrl, projectId) {
  const lines = [];
  lines.push(`Authentication/Authorization failed (${status}).`);
  lines.push('Possible causes and checks:');
  lines.push('- X_AUTH_TOKEN is invalid or expired. Obtain a fresh token and set X_AUTH_TOKEN.');
  lines.push(`- OS_PROJECT_ID is incorrect or token is not scoped for this project (current: ${projectId || '(not set)'}).`);
  lines.push(`- NOVA_BASE_URL points to a different region/endpoint (current: ${novaBaseUrl}). Override NOVA_BASE_URL if needed.`);
  lines.push('- If you changed region, ensure the token was issued for the same cloud/region tenants.');
  return lines.join(' ');
}

/**
 * Main loop: create server until its IPv4 hits desired CIDRs
 */
async function createUntilIpMatches(options) {
  const {
    novaBaseUrl,
    token,
    projectId,
    imageId,
    flavorId,
    networkId,
    keyName,
    securityGroups,
    availabilityZone,
    userDataBase64,
    serverNamePrefix,
    maxRetries,
    pollIntervalMs,
    maxPollMs,
    deleteOnFail,
    cidrs,
    microversion,
    volumeSizeGb,
    volumeType,
  } = options;

  const nova = makeNovaClient({ token, projectId, novaBaseUrl, microversion });

  console.log(`Nova: ${novaBaseUrl}/v2.1/${projectId}`);
  console.log(`Target CIDRs: ${cidrs.join(', ')}`);

  // Preflight auth check to fail fast with clear hints
  try {
    const authRes = await nova.get('/flavors', { params: { limit: 1 } });
    if (authRes.status === 401 || authRes.status === 403) {
      throw new Error(describeAuthError(authRes.status, novaBaseUrl, projectId));
    }
    if (authRes.status >= 400) {
      console.warn(`Preflight check returned ${authRes.status}: ${JSON.stringify(authRes.data)}`);
    }
  } catch (e) {
    if (e.response && (e.response.status === 401 || e.response.status === 403)) {
      throw new Error(describeAuthError(e.response.status, novaBaseUrl, projectId));
    }
    // Re-throw other errors
    throw e;
  }

  for (let attempt = 1; attempt <= maxRetries; attempt += 1) {
    const name = `${serverNamePrefix || 'vm'}-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    console.log(`\n[Attempt ${attempt}/${maxRetries}] Creating server: ${name}`);
    const body = buildCreateServerBody({
      name,
      imageId,
      flavorId,
      networkId,
      keyName,
      securityGroups,
      userDataBase64,
      availabilityZone,
      volumeSizeGb,
      volumeType,
    });

    // Debug: print payload that will be sent to Nova
     // console.log('Create server payload:', JSON.stringify(body, null, 2));

    const createRes = await nova.post('/servers', body);
    if (createRes.status === 401 || createRes.status === 403) {
      throw new Error(describeAuthError(createRes.status, novaBaseUrl, projectId));
    }
    if (createRes.status >= 400) {
      const msg = `Create server failed: ${createRes.status} ${createRes.statusText} ${JSON.stringify(createRes.data)}`;
      throw new Error(msg);
    }
    const serverId = createRes.data.server && createRes.data.server.id;
    if (!serverId) {
      throw new Error(`Create response has no server.id: ${JSON.stringify(createRes.data)}`);
    }

    console.log(`Created server id=${serverId}, waiting for ACTIVE...`);
    let server;
    try {
      server = await waitForActive(nova, serverId, pollIntervalMs, maxPollMs);
    } catch (e) {
      console.warn(`Wait failed: ${e.message}`);
      if (deleteOnFail) {
        console.log(`Deleting server ${serverId}...`);
        await deleteServer(nova, serverId, true);
      }
      // Continue next attempt
      continue;
    }

    const ipv4s = getIPv4sFromServer(server);
    console.log(`Server ACTIVE. IPv4 addresses: ${ipv4s.length ? ipv4s.join(', ') : '(none yet)'}`);

    const match = ipv4s.some((ip) => cidrs.some((c) => ipInCidr(ip, c)));
    if (match) {
      console.log(`Success: Found IP within desired ranges. Server ID: ${serverId}`);
      return { serverId, ips: ipv4s, server };
    }

    console.log(`No IP in desired ranges, will delete and retry.`);
    if (deleteOnFail) {
      await deleteServer(nova, serverId, true);
    }
  }

  throw new Error(`Max retries reached without getting an IP in desired ranges`);
}

/**
 * CLI entrypoint
 */
async function main() {
  const argv = yargs(hideBin(process.argv))
    .option('token', { type: 'string', description: 'X-Auth-Token (or env X_AUTH_TOKEN)' })
    .option('project-id', { type: 'string', description: 'OpenStack project/tenant ID (or env OS_PROJECT_ID)' })
    .option('nova-base-url', { type: 'string', description: 'Nova base URL, e.g. https://infra.mail.ru:8774' })
    .option('glance-base-url', { type: 'string', description: 'Glance base URL, e.g. https://infra.mail.ru:9292' })
    .option('neutron-base-url', { type: 'string', description: 'Neutron base URL, e.g. https://infra.mail.ru:9696' })
    .option('cinder-base-url', { type: 'string', description: 'Cinder base URL, e.g. https://infra.mail.ru:8776' })
    .option('image-id', { type: 'string', description: 'IMAGE_ID for server create', demandOption: false })
    .option('flavor-id', { type: 'string', description: 'FLAVOR_ID for server create', demandOption: false })
    .option('flavor-name', { type: 'string', description: 'FLAVOR_NAME to resolve FLAVOR_ID (or env FLAVOR_NAME)', demandOption: false })
    .option('network-id', { type: 'string', description: 'NETWORK_ID to attach' })
    .option('key-name', { type: 'string', description: 'Nova keypair name' })
    .option('security-groups', { type: 'string', description: 'Comma separated list of security group names' })
    .option('availability-zone', { type: 'string', description: 'Availability zone (optional), e.g. "GZ1" or "Москва (GZ1)"' })
    .option('user-data-b64', { type: 'string', description: 'cloud-init user_data in base64 (optional)' })
    .option('root-disk-size-gb', { type: 'number', description: 'Root disk size in GB (env ROOT_DISK_SIZE_GB or VOLUME_SIZE_GB). If set, boots from volume of this size.' })
    .option('volume-type', { type: 'string', description: 'Cinder volume type for root disk (env VOLUME_TYPE), e.g. HDD/SSD/standard' })
    .option('server-name-prefix', { type: 'string', default: 'vm', description: 'Prefix for generated server names' })
    .option('max-retries', { type: 'number', default: 50, description: 'Max attempts to recreate' })
    .option('poll-interval-ms', { type: 'number', default: 4000, description: 'Poll interval for status' })
    .option('max-poll-ms', { type: 'number', default: 600000, description: 'Max wait for ACTIVE per attempt' })
    .option('no-delete-on-fail', { type: 'boolean', default: false, description: 'Do not delete server if IP not in range' })
    .option('microversion', { type: 'string', default: '2.1', description: 'X-OpenStack-Nova-API-Version' })
    .help()
    .argv;

  const env = process.env;

  const token = argv.token || env.X_AUTH_TOKEN;
  const projectId = argv.projectId || env.OS_PROJECT_ID || argv['project-id'];
  const novaBaseUrl = argv.novaBaseUrl || env.NOVA_BASE_URL || deriveNovaBaseUrl(argv.novaBaseUrl || env.NOVA_BASE_URL);

  const imageId = argv.imageId || env.IMAGE_ID || argv['image-id'];
  let flavorId = argv.flavorId || env.FLAVOR_ID || argv['flavor-id'];
  const flavorName = argv.flavorName || env.FLAVOR_NAME || argv['flavor-name'];
  const networkId = argv.networkId || env.NETWORK_ID || argv['network-id'];
  const keyName = argv.keyName || env.KEY_NAME || argv['key-name'];
  const securityGroups = (argv.securityGroups || env.SECURITY_GROUPS || argv['security-groups'] || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const availabilityZoneRaw = argv.availabilityZone || env.AZ || env.AVAILABILITY_ZONE || argv['availability-zone'];
  const availabilityZone = availabilityZoneRaw
    ? (() => {
        const m = String(availabilityZoneRaw).match(/\(([^)]+)\)\s*$/);
        return (m && m[1]) ? m[1].trim() : String(availabilityZoneRaw).trim();
      })()
    : undefined;
  const userDataBase64 = argv.userDataB64 || env.USER_DATA_B64 || argv['user-data-b64'];

  // Root disk options (boot from volume)
  const volumeSizeGbRaw = argv.rootDiskSizeGb || env.ROOT_DISK_SIZE_GB || env.VOLUME_SIZE_GB || argv['root-disk-size-gb'];
  const volumeSizeGb = volumeSizeGbRaw !== undefined && volumeSizeGbRaw !== null && `${volumeSizeGbRaw}` !== ''
    ? Number(volumeSizeGbRaw)
    : undefined;
  const volumeType = argv.volumeType || env.VOLUME_TYPE || argv['volume-type'];

  // Cinder base URL for volume type validation
  const cinderBaseUrl = argv.cinderBaseUrl || env.CINDER_BASE_URL || deriveCinderBaseUrl(argv.cinderBaseUrl || env.CINDER_BASE_URL);

  // Validate volume type if provided; fall back to default if not found
  let effectiveVolumeType = volumeType;
  if (effectiveVolumeType) {
    try {
      const cinder = makeCinderClient({ token, cinderBaseUrl, projectId });
      const types = await listVolumeTypes(cinder);
      const found = types.find((t) => t && t.name && t.name.toLowerCase() === String(effectiveVolumeType).toLowerCase());
      if (!found) {
        console.warn(`Volume type "${effectiveVolumeType}" not found. Available types: ${types.map((t) => t.name).join(', ') || '(none)'}. Will proceed without volume type.`);
        effectiveVolumeType = undefined;
      } else {
        // Use canonical name
        effectiveVolumeType = found.name;
      }
    } catch (e) {
      console.warn(`Could not validate volume type "${effectiveVolumeType}": ${e.message}. Proceeding without volume type.`);
      effectiveVolumeType = undefined;
    }
  }

  // Resolve flavor by name if needed
  if (!flavorId && flavorName) {
    try {
      const novaLookupClient = makeNovaClient({
        token,
        projectId,
        novaBaseUrl,
        microversion: argv.microversion || env.NOVA_MICROVERSION || '2.1',
      });
      const flavors = await listFlavors(novaLookupClient);
      const found = flavors.find((f) => f.name === flavorName);
      if (!found) {
        throw new Error(`Flavor with name "${flavorName}" not found`);
      }
      flavorId = found.id;
      console.log(`Resolved FLAVOR_NAME "${flavorName}" to FLAVOR_ID ${flavorId}`);
    } catch (e) {
      console.warn(`Could not resolve FLAVOR_NAME: ${e.message}`);
    }
  }

  // If any required params are missing — fetch and show lists for user reference, then exit
  const missing = [];
  if (!imageId) missing.push('IMAGE_ID');
  if (!flavorId) missing.push('FLAVOR_ID or FLAVOR_NAME');

  if (missing.length) {
    console.error(`Missing required params: ${missing.join(', ')}`);

    console.log('\nFetching available resources for your reference...');

    // Show only what is missing
    if (!flavorId) {
      let novaListClient;
      try {
        const novaBaseUrlForList = argv.novaBaseUrl || env.NOVA_BASE_URL || novaBaseUrl;
        novaListClient = makeNovaClient({
          token,
          projectId,
          novaBaseUrl: novaBaseUrlForList,
          microversion: argv.microversion || env.NOVA_MICROVERSION || '2.1',
        });
      } catch (e) {
        console.warn(`Cannot init Nova client for listing flavors: ${e.message}`);
      }
      if (novaListClient) {
        try {
          const flavors = await listFlavors(novaListClient);
          console.log('\nFlavors (choose FLAVOR_ID or FLAVOR_NAME):');
          flavors.forEach((f) => {
            console.log(`- ${f.name} (id=${f.id}, vcpus=${f.vcpus}, ramMB=${f.ram}, diskGB=${f.disk})`);
          });
        } catch (e) {
          console.warn(`Failed to list flavors: ${e.message}`);
        }
      }
    }

    if (!imageId) {
      const glanceBaseUrl = deriveGlanceBaseUrl(argv.glanceBaseUrl || env.GLANCE_BASE_URL);
      let glanceClient;
      try {
        glanceClient = makeGlanceClient({ token, glanceBaseUrl });
      } catch (e) {
        console.warn(`Cannot init Glance client for listing images: ${e.message}`);
      }
      if (glanceClient) {
        try {
          const images = await listImages(glanceClient);
          console.log('\nImages (choose IMAGE_ID):');
          images.forEach((img) => {
            console.log(`- ${img.name || '(no-name)'} (id=${img.id}, size=${img.size || 'n/a'}, visibility=${img.visibility || 'n/a'})`);
          });
        } catch (e) {
          console.warn(`Failed to list images: ${e.message}`);
        }
      }
    }

    console.log('\nPlease set IMAGE_ID and FLAVOR_ID (or FLAVOR_NAME) via environment variables or CLI flags and rerun.');
    process.exit(2);
  }

  // Target CIDRs: MUST be provided via env CIDRS as comma-separated list
  if (!env.CIDRS || String(env.CIDRS).trim() === '') {
    console.error('Missing required env variable: CIDRS (comma-separated list)');
    process.exit(2);
  }
  const cidrs = String(env.CIDRS).split(',').map((s) => s.trim()).filter(Boolean);
  if (!cidrs.length) {
    console.error('CIDRS is empty after parsing.');
    process.exit(2);
  }

  try {
    const result = await createUntilIpMatches({
      novaBaseUrl,
      token,
      projectId,
      imageId,
      flavorId,
      networkId,
      keyName,
      securityGroups,
      availabilityZone,
      userDataBase64,
      serverNamePrefix: argv.serverNamePrefix || env.SERVER_NAME_PREFIX,
      maxRetries: Number(argv.maxRetries || env.MAX_RETRIES) || 50,
      pollIntervalMs: Number(argv.pollIntervalMs || env.POLL_INTERVAL_MS) || 4000,
      maxPollMs: Number(argv.maxPollMs || env.MAX_POLL_MS) || 600000,
      deleteOnFail: !argv.noDeleteOnFail && (env.DELETE_ON_FAIL !== 'false'),
      cidrs,
      microversion: argv.microversion || env.NOVA_MICROVERSION || '2.1',
      volumeSizeGb,
      volumeType: effectiveVolumeType,
    });

    console.log('Done.');
    console.log(JSON.stringify({
      serverId: result.serverId,
      ipv4: result.ips,
    }, null, 2));
  } catch (e) {
    console.error(`Failed: ${e.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}
