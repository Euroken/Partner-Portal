const express = require('express');
const catalyst = require('zcatalyst-sdk-node');
const https = require('https');

const app = express();

app.use(express.json());

// CORS setup to pass preflight requests
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Catalyst-App-Zuid, Z-Cloud-Zuid, Z-Cloud-User-Email, Z-Cloud-User-ID");
    
    if (req.method === "OPTIONS") {
        return res.sendStatus(204);
    }
    next();
});

/**
 * Function to get Zoho access token using refresh token.
 */
async function getZohoAccessToken() {
    return new Promise((resolve, reject) => {
        console.log("getZohoAccessToken: Attempting to get Zoho access token...");
        const clientId = process.env.ZOHO_CLIENT_ID;
        const clientSecret = process.env.ZOHO_CLIENT_SECRET;
        const refreshToken = process.env.ZOHO_REFRESH_TOKEN;

        if (!clientId || !clientSecret || !refreshToken) {
            console.error("getZohoAccessToken: Missing Zoho OAuth credentials in environment variables.");
            return reject(new Error('Missing Zoho OAuth credentials in environment variables'));
        }

        const params = new URLSearchParams({
            refresh_token: refreshToken,
            client_id: clientId,
            client_secret: clientSecret,
            grant_type: 'refresh_token'
        }).toString();

        const options = {
            hostname: 'accounts.zoho.com',
            path: `/oauth/v2/token?${params}`,
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': 0
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    const responseData = JSON.parse(data);
                    console.log(`getZohoAccessToken: Zoho token response status: ${res.statusCode}`);
                    if (res.statusCode >= 200 && res.statusCode < 300 && responseData.access_token) {
                        console.log("getZohoAccessToken: Successfully obtained access token.");
                        resolve(responseData.access_token);
                    } else {
                        console.error(`getZohoAccessToken: Failed to get access token. Response: ${JSON.stringify(responseData)}`);
                        reject(new Error(`Failed to get access token: ${responseData.error || data}`));
                    }
                } catch (e) {
                    console.error(`getZohoAccessToken: Error parsing Zoho token response: ${e.message}`);
                    reject(new Error(`Error parsing Zoho token response: ${e.message}`));
                }
            });
        });

        req.on('error', (e) => {
            console.error(`getZohoAccessToken: Request error getting Zoho access token: ${e.message}`);
            reject(new Error(`Request error getting Zoho access token: ${e.message}`));
        });

        req.end();
    });
}

/**
 * Fetch data from Zoho Analytics view using V1 API with proper filter criteria formatting.
 */
async function fetchZohoDataV1(authToken, userEmail, workspaceName, viewName, accId, accName) {
    return new Promise((resolve, reject) => {
        console.log(`fetchZohoDataV1: Fetching data from view: ${viewName}`);

        const queryParams = new URLSearchParams({
            'ZOHO_OUTPUT_FORMAT': 'JSON',
            'ZOHO_ERROR_FORMAT': 'JSON',
            'ZOHO_ACTION': 'EXPORT',
            'ZOHO_API_VERSION': '1.0'
        });

        // Configure parameters based on view name with proper criteria formatting
        let selectedColumns;
        let criteria;
        
        if (viewName === 'Channel Targets VS Achieved') {
            selectedColumns = [
                'Channel (Targets 2023).Amount',
                'Accounts.NNL Discount %',
                'Accounts.NB Discount %',
                'Accounts.Renewal Discount %',
                'New Business Won'
            ];
            // Try different column name variations for Channel Targets view
            // The actual column names might be different in this view
            criteria = `("Channel (Targets 2023).Account Name"='${accName}' AND "Accounts.Id"='${accId}')`;
        } else if (viewName === 'All Reseller SQL') {
            selectedColumns = [
                'Pipe Detail',
                'Quote stage',
                'Closing Date',
                'New Business Amount'
            ];
            // V1 API criteria format with proper filtering for Won deals only
            criteria = `("Account Name"='${accName}' AND "Account ID"='${accId}' AND "Pipe Detail"='Won' AND "Quote stage"='Closed Won')`;
        } else {
            return reject(new Error(`Unknown view name: ${viewName}`));
        }

        // Set selected columns for selective export
        queryParams.append('ZOHO_SELECTED_COLUMNS', selectedColumns.join(','));
        
        // Apply filter criteria
        queryParams.append('ZOHO_CRITERIA', criteria);

        const exportUrl = `/api/${encodeURIComponent(userEmail)}/${encodeURIComponent(workspaceName)}/${encodeURIComponent(viewName)}?${queryParams.toString()}`;

        const options = {
            hostname: 'analyticsapi.zoho.com',
            path: exportUrl,
            method: 'GET',
            headers: {
                'Authorization': `Zoho-oauthtoken ${authToken}`,
                'Content-Type': 'application/json'
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    const jsonMatch = data.match(/\{[\s\S]*\}/);
                    if (!jsonMatch) {
                        throw new Error("No JSON object found in the response data.");
                    }

                    let cleanedData = jsonMatch[0];
                    cleanedData = cleanedData.replace(/\\\//g, '/');
                    cleanedData = cleanedData.replace(/\\'/g, "'");
                    cleanedData = cleanedData.replace(/([^\\])\\([^"\\/bfnrtu])/g, '$1$2');

                    console.log(`fetchZohoDataV1: Raw response data for "${viewName}":`, cleanedData);

                    const responseData = JSON.parse(cleanedData);
                    
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        console.log(`fetchZohoDataV1: Successfully fetched data from ${viewName}. Rows received: ${responseData.data ? responseData.data.length : 0}`);
                        resolve(responseData);
                    } else {
                        console.error(`fetchZohoDataV1: Failed to fetch data. Response: ${JSON.stringify(responseData)}`);
                        reject(new Error(`Failed to fetch data from "${viewName}": ${responseData.message || responseData.error}`));
                    }
                } catch (e) {
                    console.error(`fetchZohoDataV1: Error parsing response for "${viewName}": ${e.message}`);
                    reject(new Error(`Error parsing response for "${viewName}": ${e.message}`));
                }
            });
        });

        req.on('error', (e) => {
            console.error(`fetchZohoDataV1: Request error fetching data: ${e.message}`);
            reject(new Error(`Request error fetching data: ${e.message}`));
        });

        req.end();
    });
}

/**
 * Fetch data from Zoho Analytics using V2 API with proper CONFIG parameter and criteria formatting.
 */
function fetchZohoDataV2(authToken, orgId, workspaceId, viewId, accId, accName) {
    return new Promise((resolve, reject) => {
        console.log("fetchZohoDataV2: Fetching reseller data using Zoho Analytics API v2...");

        // V2 API config object with proper criteria formatting
        const configObj = {
            criteria: `"Account Name"='${accName}' AND "Account ID"='${accId}' AND "Pipe Detail"='Won' AND "Quote stage"='Closed Won'`,
            selectedColumns: ["Pipe Detail", "Quote stage", "Closing Date", "New Business Amount"],
            responseFormat: "JSON"
        };

        const encodedConfig = Buffer.from(JSON.stringify(configObj)).toString('base64');
        const path = `/restapi/v2/workspaces/${workspaceId}/views/${viewId}/data?CONFIG=${encodeURIComponent(encodedConfig)}`;

        const options = {
            hostname: 'analyticsapi.zoho.com',
            path,
            method: 'GET',
            headers: {
                'Authorization': `Zoho-oauthtoken ${authToken}`,
                'ZANALYTICS-ORGID': orgId
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    const responseData = JSON.parse(data);

                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        console.log(`fetchZohoDataV2: Data fetch successful. Rows: ${responseData.data?.length || 0}`);
                        resolve(responseData);
                    } else {
                        console.error("fetchZohoDataV2: API error response:", responseData);
                        reject(new Error(responseData.message || 'Failed to fetch reseller data via v2'));
                    }
                } catch (e) {
                    console.error("fetchZohoDataV2: JSON parse error:", e.message);
                    reject(new Error(`Error parsing response: ${e.message}`));
                }
            });
        });

        req.on('error', (e) => {
            console.error(`fetchZohoDataV2: Request error: ${e.message}`);
            reject(new Error(`Request error: ${e.message}`));
        });

        req.end();
    });
}

/**
 * Main API endpoint to fetch analytics data for a given account.
 */
app.get('/api/fetchAnalyticsData', async (req, res) => {
    try {
        const catalystApp = catalyst.initialize(req);
        const { accId, accName } = req.query;

        if (!accId || !accName) {
            console.error("Validation failed: Account ID and Account Name are required.");
            return res.status(400).json({
                success: false,
                message: 'Account ID and Account Name are required.'
            });
        }
        
        console.log(`Request received for AccId: ${accId} and AccName: ${accName}`);

        // API configuration constants
        const userEmail = 'dominique@itrtech.africa';
        const workspaceName = 'Zoho CRM Reports';
        const targetsViewName = 'Channel Targets VS Achieved';
        const resellerViewName = 'All Reseller SQL';
        
        // V2 API constants (for future use if needed)
        const orgId = '675316788';
        const workspaceId = '1808017000000005001';
        const resellerViewId = '1808017000020198692';

        // Step 1: Get Zoho access token
        console.log("Step 1: Getting Zoho access token...");
        const authToken = await getZohoAccessToken();
        console.log("Step 1: Access token obtained successfully.");

        // Step 2: Fetch data from both analytics views in parallel using V1 API
        console.log("Step 2: Fetching data from both views in parallel using V1 API...");
        const [targetsData, resellerData] = await Promise.all([
            fetchZohoDataV1(authToken, userEmail, workspaceName, targetsViewName, accId, accName),
            fetchZohoDataV1(authToken, userEmail, workspaceName, resellerViewName, accId, accName)
        ]);
        console.log("Step 2: All analytics data fetched successfully.");

        // Step 3: Send success response
        console.log("Step 3: Sending success response to client.");
        return res.status(200).json({
            success: true,
            data: {
                targetsAchieved: targetsData,
                resellerData: resellerData
            }
        });

    } catch (error) {
        console.error('API Endpoint Error:', error.message);
        return res.status(500).json({
            success: false,
            message: 'Failed to fetch analytics data',
            error: error.message
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    console.log("Health check endpoint called.");
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
});

module.exports = app;