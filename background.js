// background.js
const SAFE_BROWSING_API_KEY = "Your api key";
const SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + SAFE_BROWSING_API_KEY;
const PHISHTANK_API_URL = "https://data.phishtank.com/data/online-valid.json";

let phishTankCache = new Set();

// Fetch PhishTank data once per hour
async function updatePhishTankData() {
    try {
        const response = await fetch(PHISHTANK_API_URL);
        const data = await response.json();
        phishTankCache = new Set(data.map(entry => entry.url));
        console.log("✅ PhishTank data updated.");
    } catch (error) {
        console.error("❌ Error updating PhishTank data:", error);
    }
}

// Run once at startup and refresh every hour
updatePhishTankData();
setInterval(updatePhishTankData, 60 * 60 * 1000);

async function checkURLSafety(url) {
    const requestBody = {
        client: {
            clientId: "PhishGuard",
            clientVersion: "1.0"
        },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
        }
    };

    try {
        // Check with Google Safe Browsing API
        const response = await fetch(SAFE_BROWSING_URL, {
            method: "POST",
            body: JSON.stringify(requestBody),
            headers: { "Content-Type": "application/json" }
        });

        const data = await response.json();
        console.log("🔍 Google Safe Browsing Response:", data);

        // If the response contains matches, it's unsafe
        if (data.matches && data.matches.length > 0) {
            return "⚠️ Unsafe URL detected!";
        }
    } catch (error) {
        console.error("❌ Error checking URL with Google Safe Browsing:", error);
    }

    return "✅ This link is safe.";
}



chrome.tabs.onUpdated.addListener(async function (tabId, changeInfo, tab) {
    if (changeInfo.url) {
        const status = await checkURLSafety(changeInfo.url);
        chrome.storage.local.set({ urlStatus: status });

        chrome.action.setBadgeText({ text: status.includes("⚠️") ? "!" : "✔", tabId });
        chrome.action.setBadgeBackgroundColor({ color: status.includes("⚠️") ? "red" : "green" });
    }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "checkURL") {
        checkURLSafety(request.url).then(status => sendResponse({ status }));
        return true;
    }
});
