const express = require("express");
const catalyst = require("zcatalyst-sdk-node");
const https = require("https");

const app = express();

// Custom middleware to parse multipart/form-data requests
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

    let body = Buffer.from([]);
    
    req.on('data', chunk => {
        body = Buffer.concat([body, chunk]);
    });

    req.on('end', () => {
        try {
            console.log("parseMultipartFormData: Request body received. Length:", body.length);
            
            req.body = {};
            req.files = []; // Array to handle multiple files

            // Define allowed file types and maximum file size
            const allowedTypes = ['application/pdf', 'image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'text/plain', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
            const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB limit

            // Split the raw body into parts based on the boundary
            const parts = body.toString('latin1').split(new RegExp(boundary + '(?:--)?\\r\\n'));

            // Process each part of the multipart data
            for (let i = 1; i < parts.length - 1; i++) {
                const part = parts[i];
                const headerEndIndex = part.indexOf('\r\n\r\n');
                if (headerEndIndex === -1) {
                    console.warn("parseMultipartFormData: Part missing header termination, skipping.");
                    continue;
                }

                const headers = part.substring(0, headerEndIndex);
                const dataString = part.substring(headerEndIndex + 4);
                console.log("parseMultipartFormData: Processing part headers:", headers.split('\r\n')[0]);

                // Parse Content-Disposition header
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
                        return res.status(400).json({ error: 'Invalid file type. Only PDF, JPG, PNG, WEBP, TXT, DOC, and DOCX files are allowed.' });
                    }

                    // Convert the file data string back to a Buffer
                    const fileBuffer = Buffer.from(dataString, 'latin1');
                    
                    // Validate file size
                    if (fileBuffer.length > MAX_FILE_SIZE) {
                        console.error(`parseMultipartFormData: File size exceeded: ${fileBuffer.length} bytes`);
                        return res.status(400).json({ error: `File size exceeds the limit of ${MAX_FILE_SIZE / (1024 * 1024)}MB.` });
                    }

                    // Store the parsed file information in req.files array
                    req.files.push({
                        fieldname: name,
                        originalname: filename,
                        encoding: '7bit',
                        mimetype: fileType,
                        buffer: fileBuffer,
                        size: fileBuffer.length
                    });
                } else { // This part is a regular form field
                    // Handle array fields (like products and required_services)
                    if (req.body[name]) {
                        // Convert to array if not already
                        if (!Array.isArray(req.body[name])) {
                            req.body[name] = [req.body[name]];
                        }
                        req.body[name].push(dataString.trim());
                    } else {
                        req.body[name] = dataString.trim();
                    }
                    console.log(`parseMultipartFormData: Found field: ${name}, Value: ${req.body[name]}`);
                }
            }
            console.log("parseMultipartFormData: Parsing complete. req.body:", req.body, "req.files count:", req.files.length);
            next();
        } catch (parseError) {
            console.error("Error parsing multipart/form-data:", parseError);
            res.status(500).json({ error: "Failed to parse multipart form data" });
        }
    });

    req.on('error', (err) => {
        console.error("Request stream error:", err);
        res.status(500).json({ error: "Request stream error" });
    });
};

// CORS headers
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
    if (req.method === "OPTIONS") {
        return res.sendStatus(204);
    }
    next();
});

app.use(express.json({ limit: '10mb' }));

/**
 * Function to get Zoho access token
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
                'Content-Length': 0
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
                    console.log("getZohoAccessToken: Response status:", res.statusCode);
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
 * Function to upload files to Zoho File System (ZFS)
 */
async function uploadFilesToZFS(accessToken, files) {
    const uploadPromises = files.map(file => uploadSingleFileToZFS(accessToken, file));
    return Promise.all(uploadPromises);
}

async function uploadSingleFileToZFS(accessToken, file) {
    return new Promise((resolve, reject) => {
        const boundary = `----WebKitFormBoundary${Math.random().toString(16).substring(2)}`;
        let postBodyStart = `--${boundary}\r\n`;
        postBodyStart += `Content-Disposition: form-data; name="file"; filename="${file.originalname}"\r\n`;
        postBodyStart += `Content-Type: ${file.mimetype}\r\n\r\n`;

        const endBoundary = `\r\n--${boundary}--\r\n`;

        const postBodyStartBuffer = Buffer.from(postBodyStart, 'binary');
        const endBoundaryBuffer = Buffer.from(endBoundary, 'binary');

        const totalLength = postBodyStartBuffer.length + file.buffer.length + endBoundaryBuffer.length;

        const options = {
            hostname: 'www.zohoapis.com',
            path: `/crm/v2/files`,
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
                    console.log("uploadSingleFileToZFS response:", JSON.stringify(response, null, 2));
                    if (response.data && response.data[0]?.code === "SUCCESS" && response.data[0]?.details?.id) {
                        resolve({
                            fileId: response.data[0].details.id,
                            fileName: file.originalname
                        });
                    } else {
                        reject(new Error(`Failed to upload file ${file.originalname} to ZFS: ${data}`));
                    }
                } catch (e) {
                    reject(new Error(`Error parsing ZFS upload response for ${file.originalname}: ${e.message}`));
                }
            });
        });

        req.on('error', (e) => {
            reject(new Error(`ZFS upload request error for ${file.originalname}: ${e.message}`));
        });

        req.write(postBodyStartBuffer);
        req.write(file.buffer);
        req.write(endBoundaryBuffer);
        req.end();
    });
}

/**
 * Function to create a lead in Zoho CRM
 */
async function createZohoLead(accessToken, formData, fileIds = []) {
    return new Promise((resolve, reject) => {

        const productsList = Array.isArray(formData.products)
        ? formData.products.map(productName => ({
            'Product': {
                'name': productName
            },
            'Quantity': 1 // Assuming a default quantity of 1
        }))
        : [];

        // Prepare the lead data
        const leadData = {
            data: [{
                // Basic lead information
                Company: formData.company,
                First_Name: formData.first_name,
                Last_Name: formData.last_name,
                Email: formData.email,
                
                // Custom fields - adjust these field names to match your Zoho CRM setup
                Province: formData.location,
                Industry: formData.industry,
                Sector: formData.sector,
                
                // Products (assuming this is a multi-select or text field in Zoho)
                Potential_Products: Array.isArray(formData.products) ? formData.products : [formData.products],
                
                // Request details
                Request_Description: formData.request_description,
                PPI_Request_type: formData.request_type,
                
                // Services (assuming this is a multi-select or text field)
                PPI_Services_Required: Array.isArray(formData.required_services) ? formData.required_services : [formData.required_services],
                
                // Demo session (boolean field)
                PPI_Does_the_end_user_require_a_demo_session: formData.demo_session === 'on' ? true : false,
                
                // Lead source
                Lead_Source: "ITR - Partner Portal",
				Reseller_Direct: "End User",

				// Lookup Mapping
				PPI_Reseller_Account: formData.reseller_account,
				PPI_Reseller_Contact: formData.reseller_contact,
                
                // Attach files if any were uploaded
                ...(fileIds.length > 0 && {
                    PPI_File_upload: fileIds.map(file => ({
                        file_id: file.fileId
                    }))
                })
            }]
        };

        const postData = JSON.stringify(leadData);
        console.log("createZohoLead: Request body:", postData);

        const options = {
            hostname: 'www.zohoapis.com',
            path: '/crm/v2/Leads',
            method: 'POST',
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`,
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
                    const response = JSON.parse(data);
                    console.log("createZohoLead: Response status:", res.statusCode, "data:", JSON.stringify(response, null, 2));
                    
                    if (res.statusCode >= 200 && res.statusCode < 300 && response.data && response.data[0]?.code === "SUCCESS") {
                        resolve({
                            leadId: response.data[0].details.id,
                            response: response
                        });
                    } else {
                        // Log detailed error information
                        if (response.data && response.data[0] && response.data[0].details) {
                            console.error('createZohoLead: Detailed error:', JSON.stringify(response.data[0].details, null, 2));
                        }
                        reject(new Error(`Failed to create lead in Zoho: ${response.message || data}`));
                    }
                } catch (e) {
                    console.error("createZohoLead: Error parsing response:", e);
                    reject(new Error(`Error parsing Zoho response: ${e.message}`));
                }
            });
        });

        req.on('error', (e) => {
            console.error("createZohoLead: Request error:", e);
            reject(new Error(`Error creating lead in Zoho: ${e.message}`));
        });

        req.write(postData);
        req.end();
    });
}

// Main endpoint for quotation form processing
app.post("/api/processQuotation", parseMultipartFormData, async (req, res) => {
    console.log("--------------------------------------------------");
    console.log("Received request to /api/processQuotation");
    try {
        console.log("Form data received:", JSON.stringify(req.body, null, 2));
        console.log("Files received:", req.files.length);

        // Validate required fields
        const requiredFields = ['first_name', 'last_name', 'email', 'company', 'location', 'industry', 'sector', 'request_description', 'request_type'];
        const missingFields = requiredFields.filter(field => !req.body[field]);
        
        if (missingFields.length > 0) {
            console.error("Missing required fields:", missingFields);
            return res.status(400).json({ 
                error: "Missing required fields", 
                fields: missingFields 
            });
        }

        // Validate that products are selected
        if (!req.body.products || (Array.isArray(req.body.products) && req.body.products.length === 0)) {
            console.error("No products selected");
            return res.status(400).json({ 
                error: "At least one product must be selected" 
            });
        }

        console.log("Getting Zoho access token...");
        const accessToken = await getZohoAccessToken();
        console.log("Zoho access token obtained successfully");

        let fileIds = [];
        
        // Upload files if any
        if (req.files && req.files.length > 0) {
            console.log("Uploading files to ZFS...");
            fileIds = await uploadFilesToZFS(accessToken, req.files);
            console.log("Files uploaded successfully:", fileIds);
        }

        console.log("Creating lead in Zoho CRM...");
        const leadResult = await createZohoLead(accessToken, req.body, fileIds);
        console.log("Lead created successfully. Lead ID:", leadResult.leadId);

        res.json({
            success: true,
            message: "Quotation request submitted successfully",
            leadId: leadResult.leadId,
            uploadedFiles: fileIds.map(f => f.fileName)
        });
        console.log("Response sent: Success");

    } catch (error) {
        console.error("Error in /api/processQuotation endpoint:", error);
        res.status(500).json({
            error: "Failed to process quotation request",
            message: error.message
        });
        console.log("Response sent: Error");
    } finally {
        console.log("--------------------------------------------------");
    }
});

// Health check endpoint
app.get("/api/health", (req, res) => {
    res.json({ 
        status: "healthy", 
        timestamp: new Date().toISOString() 
    });
});

module.exports = app;