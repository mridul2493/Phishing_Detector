document.getElementById('fetchEmails').addEventListener('click', async () => {
    const output = document.getElementById('output');
    output.textContent = "Authenticating...";

    chrome.identity.getAuthToken({ interactive: true }, async (token) => {
        if (chrome.runtime.lastError) {
            output.textContent = "Authentication error: " + chrome.runtime.lastError.message;
            return;
        }

        output.textContent = "Token acquired. Fetching emails...";

        try {
            const listResponse = await fetch(
                'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=5',
                { headers: { Authorization: `Bearer ${token}` } }
            );
            const listData = await listResponse.json();

            if (!listData.messages || listData.messages.length === 0) {
                output.textContent = "No emails found.";
                return;
            }

            let results = "";

            for (const msg of listData.messages) {
                const msgResponse = await fetch(
                    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=full`,
                    { headers: { Authorization: `Bearer ${token}` } }
                );
                const msgData = await msgResponse.json();

                // Extract plain text body (recursive)
                let body = "(No body)";
                function getPlainText(parts) {
                    for (const part of parts) {
                        if (part.mimeType === "text/plain" && part.body && part.body.data) {
                            return atob(part.body.data.replace(/-/g, '+').replace(/_/g, '/'));
                        }
                        if (part.parts) {
                            const res = getPlainText(part.parts);
                            if (res) return res;
                        }
                    }
                    return null;
                }
                if (msgData.payload.parts) {
                    body = getPlainText(msgData.payload.parts) || body;
                } else if (msgData.payload.body && msgData.payload.body.data) {
                    body = atob(msgData.payload.body.data.replace(/-/g, '+').replace(/_/g, '/'));
                }

                // Extract attachments (base64) recursively
                async function getAttachments(payload, msgId) {
                    let files = [];
                    if (payload.filename && payload.filename.length > 0 && payload.body && payload.body.attachmentId) {
                        const attachResp = await fetch(
                            `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msgId}/attachments/${payload.body.attachmentId}`,
                            { headers: { Authorization: `Bearer ${token}` } }
                        );
                        const attachData = await attachResp.json();
                        if (attachData.data) {
                            files.push({ filename: payload.filename, data: attachData.data });
                        }
                    }
                    if (payload.parts) {
                        for (const part of payload.parts) {
                            files = files.concat(await getAttachments(part, msgId));
                        }
                    }
                    return files;
                }

                const attachments = await getAttachments(msgData.payload, msg.id);

                // Send email + attachments (base64) to backend
                try {
                    const analysisResp = await fetch('http://localhost:5000/analyze-email', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email_text: body, attachments: attachments })
                    });

                    if (!analysisResp.ok) {
                        results += `Email ID: ${msg.id}\nAnalysis failed (server error)\n\n`;
                        continue;
                    }

                    const data = await analysisResp.json();

                    // Build display strings
                    const classLine = `Classification: ${data.classification} (Score: ${data.risk_score})\n`;
                    const langLine = `Detected language: ${data.detected_language}\n`;

                    // URLs
                    let urlsText = "";
                    if (data.urls_found && data.urls_found.length > 0) {
                        urlsText = "URLs detected:\n";
                        // suspicious_urls is list of {url,reason} for suspicious ones
                        // show all found URLs, mark suspicious ones with reason if present
                        const suspiciousMap = {};
                        (data.suspicious_urls || []).forEach(u => { suspiciousMap[u.url] = u.reason; });
                        data.urls_found.forEach(u => {
                            const reason = suspiciousMap[u] ? ` (${suspiciousMap[u]})` : "";
                            urlsText += `- ${u}${reason}\n`;
                        });
                    }

                    // Keywords
                    const keywordsLine = `Phishing keywords matched: ${data.phishing_keywords_matched}, Safe keywords matched: ${data.safe_keywords_matched}\n`;

                    // Attachments
                    let attachmentsText = "";
                    if (data.attachment_results && data.attachment_results.length > 0) {
                        attachmentsText = "Attachment Scan Results:\n";
                        data.attachment_results.forEach(att => {
                            // att.classification expected to be one of ✅ SAFE / ⚠ SUSPICIOUS / ❌ PHISHING or a warning string
                            attachmentsText += `- ${att.filename}: ${att.classification}\n`;
                        });
                    }

                    results += `Email ID: ${msg.id}\n${classLine}${langLine}${urlsText}${attachmentsText}${keywordsLine}Body preview: ${body.substring(0,200)}\n\n`;
                } catch (err) {
                    results += `Email ID: ${msg.id}\nAnalysis error: ${err}\n\n`;
                }
            }

            output.textContent = results;
        } catch (e) {
            output.textContent = "Error fetching emails: " + e.message;
        }
    });
});