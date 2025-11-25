
const express = require('express');
const axios = require('axios');
const winston = require('winston');
require('dotenv').config();

const app = express();
app.use(express.json({ type: ['application/json', 'application/*+json'] }));

// Logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

// Env
const {
  PORT = 3000,
  SONARQUBE_PROJECTS = '',
  SERVICENOW_INSTANCE,
  SERVICENOW_TABLE = 'incident',
  RETRY_ATTEMPTS = '3',
  RETRY_DELAY_MS = '2000',
  SERVICENOW_OAUTH_CLIENT_ID,
  SERVICENOW_OAUTH_CLIENT_SECRET,
  SERVICENOW_OAUTH_TOKEN_URL,
  SERVICENOW_OAUTH_GRANT_TYPE = 'client_credentials',
  SERVICENOW_OAUTH_SCOPE
} = process.env;

// Basic validation for required OAuth inputs
if (!SERVICENOW_INSTANCE) {
  logger.error('SERVICENOW_INSTANCE is required'); process.exit(1);
}
if (!SERVICENOW_OAUTH_CLIENT_ID || !SERVICENOW_OAUTH_CLIENT_SECRET) {
  logger.error('OAuth CLIENT_ID and CLIENT_SECRET are required'); process.exit(1);
}

// Allowed projects
const allowedProjects = SONARQUBE_PROJECTS.split(',').map(p => p.trim()).filter(Boolean);

// 🔧 Per-project routing (use sys_ids in production)
const projectIncidentConfig = {
  project1: { assignment_group: 'DevOps Team A', caller_id: 'john.doe', urgency: '2', impact: '2', severity: '2' },
  project2: { assignment_group: 'DevOps Team B', caller_id: 'jane.smith', urgency: '1', impact: '1', severity: '1' }
};
const defaultIncidentConfig = { assignment_group: 'DevOps Shared', caller_id: 'servicenow.integration', urgency: '3', impact: '3', severity: '3' };

// Axios defaults
axios.defaults.timeout = 10000; // 10s

// In-memory token cache
const tokenCache = { accessToken: null, expiresAt: 0 };

function getTokenEndpoint() {
  return SERVICENOW_OAUTH_TOKEN_URL || `${SERVICENOW_INSTANCE.replace(/\/+$/, '')}/oauth_token.do`;
}

// Fetch & cache OAuth token
async function fetchAccessToken() {
  const url = getTokenEndpoint();
  const params = new URLSearchParams();
  params.append('grant_type', SERVICENOW_OAUTH_GRANT_TYPE);
  params.append('client_id', SERVICENOW_OAUTH_CLIENT_ID);
  params.append('client_secret', SERVICENOW_OAUTH_CLIENT_SECRET);
  if (SERVICENOW_OAUTH_SCOPE) params.append('scope', SERVICENOW_OAUTH_SCOPE);

  const resp = await axios.post(url, params, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });

  const { access_token, expires_in } = resp.data || {};
  if (!access_token) {
    throw new Error(`No access_token in OAuth response: ${JSON.stringify(resp.data)}`);
  }

  // Cache token slightly earlier than actual expiry (60s safety margin)
  const ttl = Number(expires_in || 3600);
  tokenCache.accessToken = access_token;
  tokenCache.expiresAt = Date.now() + (ttl - 60) * 1000;

  logger.info({ message: 'Fetched new OAuth token', expires_in: ttl });
  return access_token;
}

async function getAccessToken() {
  if (tokenCache.accessToken && Date.now() < tokenCache.expiresAt) {
    return tokenCache.accessToken;
  }
  return await fetchAccessToken();
}

// Simple payload guard
function isSonarWebhookPayload(body) {
  return body &&
    body.project &&
    typeof body.project.key === 'string' &&
    body.qualityGate &&
    typeof body.qualityGate.status === 'string';
}

// Generic retry helper with 401 token refresh handling
async function retryRequest(fn, attempts, delayMs) {
  const attemptsNum = Number(attempts) || 3;
  const delay = Number(delayMs) || 2000;
  let lastErr;
  for (let i = 1; i <= attemptsNum; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      const status = err?.response?.status;
      const msg = err?.response?.data || err.message || String(err);

      // If 401, force token refresh on next attempt
      if (status === 401) {
        logger.warn({ message: `401 Unauthorized on attempt ${i}, invalidating token` });
        tokenCache.accessToken = null;
        tokenCache.expiresAt = 0;
      }

      logger.error({ message: `Attempt ${i} failed`, status, error: msg });
      if (i < attemptsNum) await new Promise(res => setTimeout(res, delay));
    }
  }
  throw lastErr || new Error('All retry attempts failed');
}

// Health
app.get('/health', (req, res) => res.status(200).send('OK'));

// Webhook
app.post('/sonarqube-webhook', async (req, res) => {
  const payload = req.body;

  if (!isSonarWebhookPayload(payload)) {
    logger.warn({ message: 'Invalid SonarQube payload', body: payload });
    return res.status(400).send('Invalid SonarQube webhook payload');
  }

  const projectKey = payload.project.key;
  const projectName = payload.project.name || projectKey;
  const qualityGateStatus = payload.qualityGate.status; // OK | WARN | ERROR
  const conditions = Array.isArray(payload.qualityGate.conditions) ? payload.qualityGate.conditions : [];
  const dashboardUrl = payload.url;
  const branchName = payload.branch?.name;
  const analysedAt = payload.analysedAt;
  const taskStatus = payload.status; // SUCCESS | FAILED

  // Allow-list check
  if (allowedProjects.length && !allowedProjects.includes(projectKey)) {
    logger.warn({ message: 'Project not allowed', projectKey });
    return res.status(400).send('Project not allowed');
  }

  logger.info({ message: 'Webhook received', projectKey, qualityGateStatus, branchName, analysedAt, taskStatus });

  // Skip if Quality Gate OK
  if (qualityGateStatus === 'OK') {
    logger.info({ message: 'Quality gate OK, no incident created', projectKey });
    return res.status(200).send('Quality gate OK, no incident created');
  }

  // Summarize violated conditions
  const violated = conditions
    .filter(c => c.status === 'ERROR' || c.status === 'WARN')
    .map(c => `• ${c.metric} ${c.status} (value: ${c.value ?? ''}, operator: ${c.operator || ''}, threshold: ${c.errorThreshold ?? ''})`);

  const conditionsSummary = violated.length ? violated.join('\n') : 'No violations; all conditions passed or not applicable.';

  const shortDescription = `SonarQube Quality Gate: ${qualityGateStatus} — ${projectName}${branchName ? ` [${branchName}]` : ''}`;

  const description = [
    `Project: ${projectName} (${projectKey})`,
    branchName ? `Branch: ${branchName}` : null,
    `Analysed At: ${analysedAt || 'N/A'}`,
    `Task Status: ${taskStatus || 'N/A'}`,
    `Quality Gate Status: ${qualityGateStatus}`,
    '',
    'Conditions:',
    conditionsSummary,
    '',
    dashboardUrl ? `SonarQube Dashboard: ${dashboardUrl}` : null
  ].filter(Boolean).join('\n');

  // Resolve routing
  const routing = projectIncidentConfig[projectKey] || defaultIncidentConfig;
  const { assignment_group, caller_id, urgency, impact, severity } = routing;

  // Incident creation using OAuth Bearer
  const createIncident = async () => {
    const token = await getAccessToken();
    return axios.post(
      `${SERVICENOW_INSTANCE.replace(/\/+$/, '')}/api/now/table/${SERVICENOW_TABLE}`,
      {
        short_description: shortDescription,
        description,
        category: 'software',
        subcategory: 'code_quality',
        ...(assignment_group ? { assignment_group } : {}),
        ...(caller_id ? { caller_id } : {}),
        ...(urgency ? { urgency } : {}),
        ...(impact ? { impact } : {}),
        ...(severity ? { severity } : {})
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      }
    );
  };

  try {
    const resp = await retryRequest(createIncident, RETRY_ATTEMPTS, RETRY_DELAY_MS);
    const incidentNumber = resp?.data?.result?.number;
    logger.info({ message: 'Incident created', incidentNumber, projectKey, assignment_group, caller_id, urgency, impact, severity });
    return res.status(200).json({ status: 'ok', incidentNumber, assignment_group, caller_id, urgency, impact, severity });
  } catch (err) {
    const status = err?.response?.status;
    const msg = err?.response?.data || err.message || String(err);
    logger.error({ message: 'Failed to create incident', status, error: msg });
    return res.status(500).json({ status: 'error', statusCode: status, error: msg });
  }
});

app.listen(Number(PORT), () => logger.info({ message: `Gateway running on port ${PORT}` }));
