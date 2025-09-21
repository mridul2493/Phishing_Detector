chrome.runtime.onInstalled.addListener(() => {
  console.log("Extension installed");
});

// Get Gmail token for the logged-in user
async function getGmailToken(interactive = true) {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(token);
      }
    });
  });
}

// Listen for messages from popup.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "getToken") {
    getGmailToken(true)
      .then(token => sendResponse({ token }))
      .catch(error => sendResponse({ error: error.message }));
    return true; // Keep the message channel open for async response
  }
});