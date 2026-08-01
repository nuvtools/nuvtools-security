// Google reCAPTCHA Enterprise interop — adaptive model.
//  - Default mode (score/invisible): execute() produces a token in the background, with no widget.
//  - Step-up (checkbox): rendered when the server flags the risk as high.
// enterprise.js is loaded dynamically with the score key (?render=<scoreKey>), only once.
// When loading fails (network, blocker, CSP) the functions return an empty token instead of staying
// pending: the server treats an empty token as invalid and asks for the step-up, so the failure
// reaches the user as a message. The cache is cleared on failure so the next attempt reloads.

const LOAD_TIMEOUT_MS = 10000;
const widgets = {};

let loadPromise = null;

function available() {
    return !!(window.grecaptcha && window.grecaptcha.enterprise);
}

function ensure(scoreKey) {
    if (loadPromise) return loadPromise;

    loadPromise = new Promise((resolve, reject) => {
        if (available()) { resolve(); return; }

        let settled = false;

        const succeed = () => {
            if (settled) return;
            settled = true;
            resolve();
        };

        const fail = (reason) => {
            if (settled) return;
            settled = true;
            loadPromise = null;
            reject(new Error(reason));
        };

        const timeoutId = setTimeout(
            () => fail('reCAPTCHA: timed out loading enterprise.js.'), LOAD_TIMEOUT_MS);

        const script = document.createElement('script');
        script.src = 'https://www.google.com/recaptcha/enterprise.js?render=' + encodeURIComponent(scoreKey);
        script.async = true;
        script.defer = true;

        script.onerror = () => {
            clearTimeout(timeoutId);
            fail('reCAPTCHA: failed to load enterprise.js.');
        };

        script.onload = () => {
            const wait = () => {
                if (settled) return;
                if (available() && window.grecaptcha.enterprise.ready) {
                    clearTimeout(timeoutId);
                    window.grecaptcha.enterprise.ready(succeed);
                } else {
                    setTimeout(wait, 50);
                }
            };
            wait();
        };

        document.head.appendChild(script);
    });

    return loadPromise;
}

// Score mode (invisible): returns a fresh token. Nothing is shown to the user.
export async function execute(scoreKey, action) {
    try {
        await ensure(scoreKey);
        return await window.grecaptcha.enterprise.execute(scoreKey, { action: action || 'submit' });
    } catch (e) {
        console.error('reCAPTCHA: could not produce a token.', e);
        return "";
    }
}

// Step-up: renders the "I'm not a robot" checkbox into the given element.
export async function renderCheckbox(elementId, checkboxKey, scoreKey) {
    try {
        await ensure(scoreKey);
    } catch (e) {
        console.error('reCAPTCHA: could not load the checkbox challenge.', e);
        return;
    }

    const element = document.getElementById(elementId);
    if (!element) {
        console.error(`reCAPTCHA: element "${elementId}" not found to render the checkbox.`);
        return;
    }

    if (element.childElementCount > 0) return;

    widgets[elementId] = window.grecaptcha.enterprise.render(elementId, { sitekey: checkboxKey });
}

export function getCheckboxResponse(elementId) {
    const id = widgets[elementId];
    if (id === undefined || !available()) return "";
    return window.grecaptcha.enterprise.getResponse(id) || "";
}

export function resetCheckbox(elementId) {
    const id = widgets[elementId];
    if (id === undefined || !available()) return;
    window.grecaptcha.enterprise.reset(id);
}

export function disposeCheckbox(elementId) {
    delete widgets[elementId];
}
