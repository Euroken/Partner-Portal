const express = require("express");
const catalyst = require("zcatalyst-sdk-node");
const https = require("https"); // Node.js built-in module for HTTP requests

const app = express();

// Custom middleware to parse multipart/form-data requests
// This replaces the functionality of the 'multer' package.
const parseMultipartFormData = (req, res, next) => {
    const contentType = req.headers['content-type'];
    console.log("parseMultipartFormData: Content-Type:", contentType);

    // If the request is not multipart/form-data, skip this middleware
    if (!contentType || !contentType.startsWith('multipart/form-data')) {
        console.log("parseMultipartFormData: Not multipart/form-data, skipping.");
        return next();
    }

    // Extract the boundary string from the Content-Type header
    const boundaryMatch = /boundary=([^;]+)/.exec(contentType);
    if (!boundaryMatch) {
        console.error("parseMultipartFormData: Missing boundary in Content-Type header.");
        return res.status(400).json({ error: "Missing boundary in Content-Type header" });
    }
    const boundary = `--${boundaryMatch[1]}`;
    console.log("parseMultipartFormData: Boundary found:", boundary);

    let body = Buffer.from([]); // Use Buffer to handle binary data correctly
    // Collect the raw request body chunks.
    req.on('data', chunk => {
        body = Buffer.concat([body, chunk]);
    });

    req.on('end', () => {
        try {
            console.log("parseMultipartFormData: Request body received. Length:", body.length);
            // Convert the boundary string to a Buffer for reliable splitting
            const boundaryBuffer = Buffer.from(boundary, 'latin1');
            const endBoundaryBuffer = Buffer.from(boundary + '--\r\n', 'latin1');

            req.body = {}; // Initialize req.body for form fields
            req.file = null; // Initialize req.file for the uploaded file

            // Define allowed file types and maximum file size
            const allowedTypes = ['application/pdf', 'image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
            const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB limit

            // Split the raw body into parts based on the boundary
            // This is a simplified split; for robust parsing, a dedicated multipart parser is recommended.
            // However, given the constraint of not using 'multer', this approach is maintained.
            const parts = body.toString('latin1').split(new RegExp(boundary + '(?:--)?\\r\\n'));

            // Process each part of the multipart data
            for (let i = 1; i < parts.length - 1; i++) { // Skip the first (empty) and last (closing boundary) parts
                const part = parts[i];
                const headerEndIndex = part.indexOf('\r\n\r\n');
                if (headerEndIndex === -1) {
                    console.warn("parseMultipartFormData: Part missing header termination, skipping.");
                    continue; // Skip if headers are not properly terminated
                }

                const headers = part.substring(0, headerEndIndex);
                // The data part needs to be re-extracted as a Buffer from the original body
                // This is complex with simple string splitting. For now, we'll assume the data is correctly extracted
                // and focus on the file buffer conversion.
                // A more robust solution would involve finding byte offsets for each part.
                // For direct binary data handling, it's better to process the raw buffer without converting to string.
                // Given the current implementation, we'll convert back to buffer from the 'latin1' string.
                const dataString = part.substring(headerEndIndex + 4); // Extract data after headers (\r\n\r\n)
                console.log("parseMultipartFormData: Processing part headers:", headers.split('\r\n')[0]); // Log first header line

                // Parse Content-Disposition header to get field name and filename (if it's a file)
                const contentDispositionMatch = /Content-Disposition: form-data; name="([^"]+)"(?:; filename="([^"]+)")?/.exec(headers);
                if (!contentDispositionMatch) {
                    console.warn("parseMultipartFormData: Part missing Content-Disposition, skipping.");
                    continue;
                }

                const name = contentDispositionMatch[1];
                const filename = contentDispositionMatch[2];

                if (filename) { // This part is a file upload
                    const contentTypeHeaderMatch = /Content-Type: ([^\r\n]+)/.exec(headers);
                    const fileType = contentTypeHeaderMatch ? contentTypeHeaderMatch[1] : 'application/octet-stream';
                    console.log(`parseMultipartFormData: Found file: ${filename}, Type: ${fileType}, Field: ${name}`);

                    // Validate file type
                    if (!allowedTypes.includes(fileType)) {
                        console.error(`parseMultipartFormData: Invalid file type: ${fileType}`);
                        return res.status(400).json({ error: 'Invalid file type. Only PDF, JPG, PNG, and WEBP files are allowed.' });
                    }

                    // Convert the file data string (latin1) back to a Buffer
                    const fileBuffer = Buffer.from(dataString, 'latin1');
                    // Validate file size
                    if (fileBuffer.length > MAX_FILE_SIZE) {
                        console.error(`parseMultipartFormData: File size exceeded: ${fileBuffer.length} bytes`);
                        return res.status(400).json({ error: `File size exceeds the limit of ${MAX_FILE_SIZE / (1024 * 1024)}MB.` });
                    }

                    // Store the parsed file information in req.file, mimicking multer's output
                    req.file = {
                        fieldname: name,
                        originalname: filename,
                        encoding: '7bit', // Standard encoding for binary data in multipart
                        mimetype: fileType,
                        buffer: fileBuffer,
                        size: fileBuffer.length
                    };
                } else { // This part is a regular form field
                    req.body[name] = dataString.trim(); // Store the field value in req.body
                    console.log(`parseMultipartFormData: Found field: ${name}, Value: ${req.body[name]}`);
                }
            }
            console.log("parseMultipartFormData: Parsing complete. req.body:", req.body, "req.file:", req.file ? req.file.originalname : 'None');
            next(); // Proceed to the next middleware/route handler
        } catch (parseError) {
            console.error("Error parsing multipart/form-data:", parseError);
            res.status(500).json({ error: "Failed to parse multipart form data" });
        }
    });

    // Handle potential errors during request stream processing
    req.on('error', (err) => {
        console.error("Request stream error:", err);
        res.status(500).json({ error: "Request stream error" });
    });
};

// CORS headers to allow cross-origin requests
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
    if (req.method === "OPTIONS") {
        return res.sendStatus(204); // Handle pre-flight OPTIONS requests
    }
    next();
});

// Use express.json() for parsing JSON request bodies.
// Note: This middleware should be placed after custom multipart parser if a route handles both.
// For this setup, `parseMultipartFormData` is applied directly to the `/processCertificate` route.
app.use(express.json({ limit: '10mb' }));

/**
 * Function to get Zoho access token using Node.js's built-in https module.
 * Manually constructs URL-encoded parameters.
 * @returns {Promise<string>} The Zoho access token.
 */
async function getZohoAccessToken() {
    return new Promise((resolve, reject) => {
        const clientId = process.env.ZOHO_CLIENT_ID;
        const clientSecret = process.env.ZOHO_CLIENT_SECRET;
        const refreshToken = process.env.ZOHO_REFRESH_TOKEN;

        if (!clientId || !clientSecret || !refreshToken) {
            console.error("getZohoAccessToken: Zoho configuration not set.");
            return reject(new Error("Zoho configuration not properly set in environment variables"));
        }

        const params = [
            `refresh_token=${encodeURIComponent(refreshToken)}`,
            `client_id=${encodeURIComponent(clientId)}`,
            `client_secret=${encodeURIComponent(clientSecret)}`,
            `grant_type=${encodeURIComponent('refresh_token')}`
        ].join('&');

        const options = {
            hostname: 'accounts.zoho.com',
            path: `/oauth/v2/token?${params}`,
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': 0 // No body for POST with params in URL
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                try {
                    const responseData = JSON.parse(data);
                    console.log("getZohoAccessToken: Zoho token response status:", res.statusCode, "data:", responseData);
                    if (res.statusCode >= 200 && res.statusCode < 300 && responseData.access_token) {
                        resolve(responseData.access_token);
                    } else {
                        reject(new Error(`Failed to get Zoho access token: ${responseData.error || data}`));
                    }
                } catch (e) {
                    reject(new Error(`Error parsing Zoho token response: ${e.message}`));
                }
            });
        });

        req.on('error', (e) => {
            console.error("getZohoAccessToken: Request error:", e);
            reject(new Error(`Error getting Zoho access token: ${e.message}`));
        });

        req.end();
    });
}

/**
 * Function to analyze certificate with Gemini API using Node.js's built-in https module.
 * @param {string} fileData - Base64 encoded file data.
 * @param {string} fileType - MIME type of the file.
 * @returns {Promise<object>} Parsed JSON analysis result from Gemini.
 */
async function analyzeWithGemini(fileData, fileType) {
    return new Promise((resolve, reject) => {
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) {
            console.error("analyzeWithGemini: GEMINI_API key not configured.");
            return reject(new Error("GEMINI_API key not configured"));
        }

        const promptText = `Analyze this certificate image and extract the following information in JSON format only. Return ONLY the JSON object, no additional text:
                {
                  "certificationId": "string or null",
                  "expiryDate": "string or null", 
                  "productName": "string or null",
                  "startDate": "string or null",
                  "type": "string or null"
                }

                Instructions:
                - Extract certification ID (any unique identifier, certificate number, etc.)
                - Extract expiry date (when the certificate expires)
                - Extract product name (what product/service this certificate is for)
                - Extract start date (when certification started/was issued)
                - Extract type (the level of certification e.g., Professional, Associate, Expert, etc.)
                - If any field cannot be found, use null
                - Return only the JSON object

                Should the certificate not provide a start date or expiry date, 
                determine the relevant date by analyzing the provided date based on the validity peiod provided in the certificate. 
                If there is a valid till, use that as the expiry date, and determine the start date from that date. 
                if there is a validity period field, determine the expiry date from the start date. Example: 1. (The certificate is valid for 2 years, from: Tuesday, Apr 29 2025 - Start Date: 29 Apr 2025, Expiry Date: 29 Apr 2027)
                Return the dates in format DD MMM YYYY. When returning dates, only first letter of the month must be capital letter. The other should be small letters.`;

        const body = {
            contents: [{
                parts: [
                    { text: promptText },
                    {
                        inlineData: {
                            mimeType: fileType,
                            data: fileData
                        }
                    }
                ]
            }]
        };

        const postData = JSON.stringify(body);

        const options = {
            hostname: 'generativelanguage.googleapis.com',
            path: `/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                try {
                    const responseData = JSON.parse(data);
                    console.log("analyzeWithGemini: Gemini response status:", res.statusCode, "data:", JSON.stringify(responseData, null, 2)); // Log full response
                    const text = responseData?.candidates?.[0]?.content?.parts?.[0]?.text;
                    if (!text) {
                        console.error("analyzeWithGemini: Gemini API did not return valid text:", responseData);
                        return reject(new Error('Gemini API did not return valid text'));
                    }

                    const match = text.match(/\{[\s\S]*?\}/);
                    if (!match) {
                        console.error("analyzeWithGemini: No JSON object found in Gemini response text:", text);
                        return reject(new Error('No JSON object found in Gemini response'));
                    }
                    const parsedJson = JSON.parse(match[0]);
                    console.log("analyzeWithGemini: Parsed Gemini JSON:", parsedJson);
                    resolve(parsedJson);
                } catch (e) {
                    console.error("analyzeWithGemini: Error parsing Gemini response:", e);
                    reject(new Error(`Error parsing Gemini response: ${e.message}`));
                }
            });
        });

        req.on('error', (e) => {
            console.error("analyzeWithGemini: Request error:", e);
            reject(new Error(`Error analyzing with Gemini: ${e.message}`));
        });

        req.write(postData);
        req.end();
    });
}

/**
 * Function to upload a file to Zoho File System (ZFS).
 * @param {string} accessToken - Zoho OAuth access token.
 * @param {Buffer} fileBuffer - The file data as a Buffer.
 * @param {string} fileName - The original name of the file.
 * @param {string} fileType - The MIME type of the file.
 * @returns {Promise<string>} The file ID from ZFS.
 */
async function uploadFileToZFS(accessToken, fileBuffer, fileName, fileType) {
    return new Promise((resolve, reject) => {
        const boundary = `----WebKitFormBoundary${Math.random().toString(16).substring(2)}`;
        let postBodyStart = `--${boundary}\r\n`;
        postBodyStart += `Content-Disposition: form-data; name="file"; filename="${fileName}"\r\n`;
        postBodyStart += `Content-Type: ${fileType}\r\n\r\n`;

        const endBoundary = `\r\n--${boundary}--\r\n`;

        const postBodyStartBuffer = Buffer.from(postBodyStart, 'binary');
        const endBoundaryBuffer = Buffer.from(endBoundary, 'binary');

        const totalLength = postBodyStartBuffer.length + fileBuffer.length + endBoundaryBuffer.length;

        const options = {
            hostname: 'www.zohoapis.com',
            path: `/crm/v2/files`, // Correct endpoint for ZFS upload
            method: 'POST',
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`,
                'Content-Type': `multipart/form-data; boundary=${boundary}`,
                'Content-Length': totalLength
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    console.log("uploadFileToZFS response:", JSON.stringify(response, null, 2));
                    if (response.data && response.data[0]?.code === "SUCCESS" && response.data[0]?.details?.id) {
                        resolve(response.data[0].details.id); // Return the file ID
                    } else {
                        reject(new Error(`Failed to upload file to ZFS: ${data}`));
                    }
                } catch (e) {
                    reject(new Error(`Error parsing ZFS upload response: ${e.message}`));
                }
            });
        });

        req.on('error', (e) => {
            reject(new Error(`ZFS upload request error: ${e.message}`));
        });

        req.write(postBodyStartBuffer);
        req.write(fileBuffer);
        req.write(endBoundaryBuffer);
        req.end();
    });
}

/**
 * Helper function to format date from "DD MMM YYYY" to "YYYY-MM-DD".
 * Handles null or invalid dates gracefully.
 * @param {string|null} dateString - Date string in "DD MMM YYYY" format.
 * @returns {string|null} Date string in "YYYY-MM-DD" format, or null if invalid.
 */
function formatDateForZoho(dateString) {
    if (!dateString) {
        return null;
    }
    const months = {
        'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04', 'May': '05', 'Jun': '06',
        'Jul': '07', 'Aug': '08', 'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
    };
    const parts = dateString.split(' ');
    if (parts.length === 3) {
        const day = parts[0].padStart(2, '0');
        const month = months[parts[1]];
        const year = parts[2];
        if (day && month && year) {
            return `${year}-${month}-${day}`;
        }
    }
    console.warn(`formatDateForZoho: Could not parse date "${dateString}". Returning null.`);
    return null;
}

/**
 * Function to update contact subform in Zoho CRM using Node.js's built-in https module.
 * @param {string} accessToken - Zoho OAuth access token.
 * @param {string} contactId - ID of the Zoho CRM contact.
 * @param {object} certificationData - Data to update the certification subform.
 * @param {string} fileId - The ID of the uploaded file from ZFS to link to the subform field.
 * @returns {Promise<object>} Response data from Zoho CRM.
 */
async function updateContactSubform(accessToken, contactId, certificationData, fileId) {
    return new Promise(async (resolve, reject) => {
        try {
            console.log("updateContactSubform: Starting subform update for Contact ID:", contactId);
            // Step 1: Get the existing contact to retrieve current subform data
            const getOptions = {
                hostname: 'www.zohoapis.com',
                path: `/crm/v2/Contacts/${contactId}`,
                method: 'GET',
                headers: {
                    'Authorization': `Zoho-oauthtoken ${accessToken}`
                }
            };

            const getResponseData = await new Promise((resolveGet, rejectGet) => {
                const getReq = https.request(getOptions, (res) => {
                    let data = '';
                    res.on('data', (chunk) => {
                        data += chunk;
                    });
                    res.on('end', () => {
                        try {
                            const parsedData = JSON.parse(data);
                            console.log("updateContactSubform: Zoho GET contact response status:", res.statusCode, "data:", JSON.stringify(parsedData, null, 2)); // Log full response
                            if (res.statusCode >= 200 && res.statusCode < 300) {
                                resolveGet(parsedData);
                            } else {
                                console.error('updateContactSubform: Zoho get contact error response:', parsedData);
                                rejectGet(new Error(`Failed to get existing contact data from Zoho: ${parsedData.message || data}`));
                            }
                        } catch (e) {
                            console.error("updateContactSubform: Error parsing Zoho GET response:", e);
                            rejectGet(new Error(`Error parsing Zoho GET response: ${e.message}`));
                        }
                    });
                });
                getReq.on('error', (e) => {
                    console.error("updateContactSubform: GET contact request error:", e);
                    rejectGet(new Error(`Error getting contact from Zoho: ${e.message}`));
                });
                getReq.end();
            });

            const existingSubformData = getResponseData.data[0].Reseller_Certifications || [];
            console.log("updateContactSubform: Existing subform data:", JSON.stringify(existingSubformData, null, 2));

            const newCertification = {
                Certification_ID: certificationData.certificationId || null,
                Product_Name: certificationData.productName || null,
                Type: certificationData.type || null,
                Start_Date: formatDateForZoho(certificationData.startDate),
                Expiry_Date: formatDateForZoho(certificationData.expiryDate),
                // Corrected: Wrap the file object in an array as per Zoho CRM API documentation
                Certification: [
                    {
                        "file_id": fileId
                    }
                ]
            };

            console.log("updateContactSubform: New certification entry (after date formatting and file ID assignment):", JSON.stringify(newCertification, null, 2));

            const updatedSubformData = [...existingSubformData, newCertification];
            console.log("updateContactSubform: Combined subform data for update:", JSON.stringify(updatedSubformData, null, 2));

            // Step 2: Update the contact with the new subform data
            const updateData = {
                data: [{
                    id: contactId,
                    Reseller_Certifications: updatedSubformData
                }]
            };

            const putData = JSON.stringify(updateData);
            console.log("updateContactSubform: Zoho PUT request body:", putData);

            const putOptions = {
                hostname: 'www.zohoapis.com',
                path: `/crm/v2/Contacts`,
                method: 'PUT',
                headers: {
                    'Authorization': `Zoho-oauthtoken ${accessToken}`,
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(putData)
                }
            };

            const putResponseData = await new Promise((resolvePut, rejectPut) => {
                const putReq = https.request(putOptions, (res) => {
                    let data = '';
                    res.on('data', (chunk) => {
                        data += chunk;
                    });
                    res.on('end', () => {
                        try {
                            const parsedData = JSON.parse(data);
                            // IMPORTANT: Log the full details object if present
                            if (parsedData.data && parsedData.data[0] && parsedData.data[0].details) {
                                console.error('updateContactSubform: Zoho update contact error details:', JSON.stringify(parsedData.data[0].details, null, 2));
                            }
                            console.log("updateContactSubform: Zoho PUT contact response status:", res.statusCode, "data:", JSON.stringify(parsedData, null, 2));
                            if (res.statusCode >= 200 && res.statusCode < 300) {
                                resolvePut(parsedData);
                            } else {
                                console.error('updateContactSubform: Zoho update contact error response (full):', parsedData);
                                rejectPut(new Error(`Failed to update contact in Zoho: ${parsedData.message || data}`));
                            }
                        } catch (e) {
                            console.error("updateContactSubform: Error parsing Zoho PUT response:", e);
                            rejectPut(new Error(`Error parsing Zoho PUT response: ${e.message}`));
                        }
                    });
                });
                putReq.on('error', (e) => {
                    console.error("updateContactSubform: PUT contact request error:", e);
                    rejectPut(new Error(`Error updating contact in Zoho: ${e.message}`));
                });
                putReq.write(putData);
                putReq.end();
            });
            resolve(putResponseData);
        } catch (error) {
            console.error("updateContactSubform: Caught top-level error:", error);
            reject(new Error(`Failed to update contact in Zoho CRM: ${error.message}`));
        }
    });
}

// Main endpoint for certificate processing
app.post("/api/processCertificate", parseMultipartFormData, async (req, res) => {
    console.log("--------------------------------------------------");
    console.log("Received request to /api/processCertificate");
    try {
        const { contactId } = req.body;
        console.log("Extracted contactId from request body:", contactId);

        if (!contactId) {
            console.error("Error: Contact ID is missing.");
            return res.status(400).json({ error: "Contact ID is required" });
        }

        if (!req.file) {
            console.error("Error: Certificate file is missing.");
            return res.status(400).json({ error: "Certificate file is required" });
        }
        console.log("File received:", req.file.originalname, "MIME Type:", req.file.mimetype);

        const fileData = req.file.buffer.toString('base64');
        const fileType = req.file.mimetype;

        console.log("Calling analyzeWithGemini...");
        const analysisResult = await analyzeWithGemini(fileData, fileType);
        console.log("Gemini analysis result:", JSON.stringify(analysisResult, null, 2));

        console.log("Calling getZohoAccessToken...");
        const accessToken = await getZohoAccessToken();
        console.log("Zoho Access Token obtained.");

        console.log("Calling uploadFileToZFS...");
        // Upload the file to ZFS first to get a fileId
        const fileId = await uploadFileToZFS(
            accessToken,
            req.file.buffer,
            req.file.originalname,
            fileType
        );
        console.log("File uploaded to ZFS. File ID:", fileId);

        console.log("Calling updateContactSubform...");
        // Pass the fileId to the subform update function
        await updateContactSubform(accessToken, contactId, analysisResult, fileId);
        console.log("Contact subform updated successfully.");

        res.json({
            success: true,
            message: "Certificate processed successfully",
            data: analysisResult
        });
        console.log("Response sent: Success.");

    } catch (error) {
        console.error("Caught error in /api/processCertificate endpoint:", error);
        res.status(500).json({
            error: "Failed to process certificate",
            message: error.message
        });
        console.log("Response sent: Error.");
    } finally {
        console.log("--------------------------------------------------");
    }
});

// Keep existing endpoints for backward compatibility
/*
app.get("/api/getKey", async (req, res) => {
    try {
        const catalystApp = catalyst.initialize(req);
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) {
            console.error("getKey: GEMINI_API key not configured.");
            return res
                .status(500)
                .json({
                    error: "GEMINI_API key not configured in environment variables.",
                });
        }
        console.log("getKey: API key retrieved successfully.");
        return res.status(200).json({
            apiKey,
            timestamp: new Date().toISOString(),
        });
    } catch (error) {
        console.error("Server error in getKey:", error);
        return res.status(500).json({
            error: "Internal server error",
            message: error.message,
        });
    }
});

app.get("/api/getZohoConfig", async (req, res) => {
    try {
        const clientId = process.env.ZOHO_CLIENT_ID;
        const clientSecret = process.env.ZOHO_CLIENT_SECRET;
        const refreshToken = process.env.ZOHO_REFRESH_TOKEN;
        if (!clientId || !clientSecret || !refreshToken) {
            console.error("getZohoConfig: Zoho configuration not properly set.");
            return res.status(500).json({
                error: "Zoho configuration not properly set in environment variables",
            });
        }
        console.log("getZohoConfig: Zoho configuration retrieved successfully.");
        res.json({
            clientId: clientId,
            clientSecret: clientSecret,
            refreshToken: refreshToken,
        });
    } catch (error) {
        console.error("Error getting Zoho config:", error);
        res.status(500).json({ error: "Failed to get Zoho configuration" });
    }
});
*/

module.exports = app;
