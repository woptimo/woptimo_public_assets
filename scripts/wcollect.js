/**
 * WCollect — collecteur web analytics first-party (Woptimo)
 *
 * Envoie en POST des lots d'événements vers
 * https://thx.woptimo.com/wcollect, au format JSON WCollect.
 *
 * CORS / Origin
 * -------------
 * Un POST `Content-Type: application/json` déclenche un preflight OPTIONS.
 * Le client sGTM (webhook catcher) ne répond pas à OPTIONS → échec CORS.
 * Ce script n'envoie donc QUE des requêtes « simples » :
 *   POST + Content-Type: text/plain;charset=UTF-8 + body JSON
 * (même stratégie que GA4 / gtag). Priorité : sendBeacon → fetch keepalive
 * no-cors → XHR. Aucun header custom, credentials omises.
 *
 * Compatibilité : navigateurs depuis ~2016 (Chrome 52+, Firefox 48+,
 * Safari 10+, Edge 14+). Pas d'optional chaining, ni de ??, ni d'async/await.
 *
 * Usage
 * -----
 *   <script src="wcollect.min.js" data-project-id="mon_site" async></script>
 *   WCollect.init({ projectId: 'mon_site' });
 *   WCollect.track('button_click', { category: 'engagement', properties: { label: 'cta' } });
 *   WCollect.identify('user-123', { email: 'user@example.com' });
 *   WCollect.setConsent({ analytics: true, marketing: false });
 *
 * L'hôte de collecte est figé : thx.woptimo.com (HTTPS). Un `endpoint`
 * optionnel n'est accepté que s'il pointe vers cet hôte.
 *
 * File d'attente avant chargement :
 *   window.WCollect = window.WCollect || function () { (WCollect.q = WCollect.q || []).push(arguments); };
 *
 * @version 1.1.0
 */
(function (window, document) {
    'use strict';

    var SDK_VERSION = '1.1.0';
    var COLLECT_URL = 'https://thx.woptimo.com/wcollect';
    var ALLOWED_HOST = 'thx.woptimo.com';
    var DEFAULT_PATH = '/wcollect';
    var COOKIE_AID = '_wc_aid';
    var COOKIE_AID_CREATED = '_wc_aid_at';
    var STORAGE_OPT_OUT = 'wcollect_optout';
    var AID_MAX_AGE_SEC = 13 * 30 * 24 * 60 * 60;
    var BATCH_MAX_EVENTS = 10;
    var BATCH_MAX_BYTES = 60000;
    var FLUSH_MS = 2000;
    var TEXT_PLAIN = 'text/plain;charset=UTF-8';
    var SENSITIVE_QS = {
        password: 1, passwd: 1, pwd: 1, email: 1, mail: 1, token: 1,
        access_token: 1, refresh_token: 1, api_key: 1, apikey: 1,
        authorization: 1, auth: 1, session: 1, sessionid: 1, sid: 1,
        jwt: 1, otp: 1, pin: 1, card: 1, cvv: 1, cvc: 1, iban: 1,
        phone: 1, tel: 1, secret: 1, code: 1
    };
    var CLICK_ID_KEYS = [
        'gclid', 'dclid', 'wbraid', 'gbraid', 'fbclid', 'msclkid',
        'ttclid', 'li_fat_id', 'twclid', 'ScCid'
    ];

    var nav = window.navigator || {};
    var loc = window.location;
    var cryptoObj = window.crypto || window.msCrypto;

    var state = {
        ready: false,
        projectId: '',
        endpoint: COLLECT_URL,
        debug: false,
        autoPageView: true,
        autoSpa: true,
        queue: [],
        flushTimer: null,
        sending: false,
        anonymousId: '',
        deviceId: '',
        userId: null,
        userProperties: {},
        userData: {},
        consent: { analytics: true, marketing: null },
        lastTrackedUrl: '',
        pageEnteredAt: nowIso(),
        pageEnteredMs: Date.now(),
        hidden: false,
        lastHideSentAt: 0,
        listenersBound: false,
        contextCache: null
    };

    function log() {
        if (!state.debug || !window.console) {
            return;
        }
        var args = Array.prototype.slice.call(arguments);
        args.unshift('[wcollect]');
        if (console.debug) {
            console.debug.apply(console, args);
        } else {
            console.log.apply(console, args);
        }
    }

    function nowIso() {
        try {
            return new Date().toISOString();
        } catch (e) {
            return new Date().toUTCString();
        }
    }

    function isHttps() {
        return loc.protocol === 'https:';
    }

    function isOptedOut() {
        try {
            if (window.localStorage && localStorage.getItem(STORAGE_OPT_OUT) === '1') {
                return true;
            }
        } catch (e) { /* private mode */ }
        return readCookie(COOKIE_AID) === 'optout';
    }

    function setOptOut(flag) {
        try {
            if (window.localStorage) {
                if (flag) {
                    localStorage.setItem(STORAGE_OPT_OUT, '1');
                } else {
                    localStorage.removeItem(STORAGE_OPT_OUT);
                }
            }
        } catch (e) { /* ignore */ }
        if (flag) {
            writeCookie(COOKIE_AID, 'optout', AID_MAX_AGE_SEC);
        }
    }

    function readCookie(name) {
        var parts = ('; ' + document.cookie).split('; ' + name + '=');
        if (parts.length < 2) {
            return '';
        }
        return decodeURIComponent(parts.pop().split(';').shift());
    }

    function writeCookie(name, value, maxAgeSec) {
        var cookie = name + '=' + encodeURIComponent(value) +
            '; path=/' +
            '; max-age=' + maxAgeSec +
            '; SameSite=Lax';
        if (isHttps()) {
            cookie += '; Secure';
        }
        document.cookie = cookie;
    }

    function storageGet(key) {
        try {
            return window.localStorage ? localStorage.getItem(key) : null;
        } catch (e) {
            return null;
        }
    }

    function storageSet(key, value) {
        try {
            if (window.localStorage) {
                localStorage.setItem(key, value);
            }
        } catch (e) { /* ignore */ }
    }

    function uuidV4() {
        var buf = new Uint8Array(16);
        var i;
        if (cryptoObj && cryptoObj.getRandomValues) {
            cryptoObj.getRandomValues(buf);
        } else {
            for (i = 0; i < 16; i++) {
                buf[i] = Math.floor(Math.random() * 256);
            }
        }
        buf[6] = (buf[6] & 0x0f) | 0x40;
        buf[8] = (buf[8] & 0x3f) | 0x80;
        var hex = '';
        for (i = 0; i < 16; i++) {
            hex += ('0' + buf[i].toString(16)).slice(-2);
        }
        return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' +
            hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
    }

    function getOrCreateAnonymousId() {
        var existing = readCookie(COOKIE_AID);
        if (existing && existing !== 'optout' && existing.length >= 8) {
            return existing;
        }
        var stored = storageGet(COOKIE_AID);
        if (stored && stored !== 'optout' && stored.length >= 8) {
            var createdAt = storageGet(COOKIE_AID_CREATED);
            var remaining = remainingMaxAge(createdAt);
            writeCookie(COOKIE_AID, stored, remaining);
            return stored;
        }
        var id = uuidV4();
        var created = String(Date.now());
        writeCookie(COOKIE_AID, id, AID_MAX_AGE_SEC);
        writeCookie(COOKIE_AID_CREATED, created, AID_MAX_AGE_SEC);
        storageSet(COOKIE_AID, id);
        storageSet(COOKIE_AID_CREATED, created);
        return id;
    }

    function remainingMaxAge(createdAtMs) {
        var created = parseInt(createdAtMs, 10);
        if (!created) {
            return AID_MAX_AGE_SEC;
        }
        var elapsed = Math.floor((Date.now() - created) / 1000);
        var left = AID_MAX_AGE_SEC - elapsed;
        return left > 60 ? left : 60;
    }

    function sanitizeQuery(search) {
        if (!search) {
            return '';
        }
        var raw = search.charAt(0) === '?' ? search.slice(1) : search;
        if (!raw) {
            return '';
        }
        var kept = [];
        var pairs = raw.split('&');
        var i;
        for (i = 0; i < pairs.length; i++) {
            if (!pairs[i]) {
                continue;
            }
            var kv = pairs[i].split('=');
            var key = decodeURIComponent((kv[0] || '').replace(/\+/g, ' ')).toLowerCase();
            if (SENSITIVE_QS[key]) {
                continue;
            }
            kept.push(pairs[i]);
        }
        return kept.length ? '?' + kept.join('&') : '';
    }

    function sanitizeUrl(href) {
        if (!href) {
            return '';
        }
        try {
            var parsed = parseUrl(href);
            if (!parsed) {
                return href.split('#')[0];
            }
            return parsed.protocol + '//' + parsed.host + parsed.pathname +
                sanitizeQuery(parsed.search);
        } catch (e) {
            return String(href).split('#')[0];
        }
    }

    function parseUrl(href) {
        if (window.URL) {
            try {
                return new URL(href, loc.href);
            } catch (e) { /* fallback */ }
        }
        var a = document.createElement('a');
        a.href = href;
        return {
            protocol: a.protocol,
            host: a.host,
            hostname: a.hostname,
            pathname: a.pathname,
            search: a.search,
            hash: a.hash
        };
    }

    function getQueryParam(search, name) {
        var raw = (search || loc.search || '').replace(/^\?/, '');
        if (!raw) {
            return '';
        }
        var pairs = raw.split('&');
        var i;
        for (i = 0; i < pairs.length; i++) {
            var kv = pairs[i].split('=');
            if (decodeURIComponent((kv[0] || '').replace(/\+/g, ' ')) === name) {
                return decodeURIComponent((kv[1] || '').replace(/\+/g, ' '));
            }
        }
        return '';
    }

    function parseUa(ua) {
        ua = ua || '';
        var browserName = 'Other';
        var osName = 'Other';
        var osVersion = '';

        if (/edg\//i.test(ua)) {
            browserName = 'Edge';
        } else if (/opr\//i.test(ua) || /opera/i.test(ua)) {
            browserName = 'Opera';
        } else if (/chrome|crios/i.test(ua) && !/edg/i.test(ua)) {
            browserName = 'Chrome';
        } else if (/safari/i.test(ua) && !/chrome|crios|android/i.test(ua)) {
            browserName = 'Safari';
        } else if (/firefox|fxios/i.test(ua)) {
            browserName = 'Firefox';
        } else if (/msie|trident/i.test(ua)) {
            browserName = 'IE';
        }

        var m;
        if (/windows nt 10/i.test(ua)) {
            osName = 'Windows';
            osVersion = '10';
        } else if (/windows nt 6\.3/i.test(ua)) {
            osName = 'Windows';
            osVersion = '8.1';
        } else if (/windows nt 6\.1/i.test(ua)) {
            osName = 'Windows';
            osVersion = '7';
        } else if (/android\s([\d._]+)/i.test(ua)) {
            osName = 'Android';
            m = ua.match(/android\s([\d._]+)/i);
            osVersion = m ? m[1] : '';
        } else if (/iphone|ipad|ipod/i.test(ua)) {
            osName = 'iOS';
            m = ua.match(/os\s([\d_]+)/i);
            osVersion = m ? m[1].replace(/_/g, '.') : '';
        } else if (/mac os x\s([\d_]+)/i.test(ua)) {
            osName = 'macOS';
            m = ua.match(/mac os x\s([\d_]+)/i);
            osVersion = m ? m[1].replace(/_/g, '.') : '';
        } else if (/linux/i.test(ua)) {
            osName = 'Linux';
        }

        return { browserName: browserName, osName: osName, osVersion: osVersion };
    }

    function getNetwork() {
        var c = nav.connection || nav.mozConnection || nav.webkitConnection;
        if (!c) {
            return {};
        }
        var out = {};
        if (c.effectiveType) {
            out.effectiveType = String(c.effectiveType);
        }
        if (typeof c.downlink === 'number') {
            out.downlink = c.downlink;
        }
        if (typeof c.rtt === 'number') {
            out.rtt = c.rtt;
        }
        if (typeof c.saveData === 'boolean') {
            out.saveData = c.saveData;
        }
        return out;
    }

    function getScreen() {
        var s = window.screen || {};
        return {
            width: s.width || 0,
            height: s.height || 0,
            availWidth: s.availWidth || 0,
            availHeight: s.availHeight || 0,
            colorDepth: s.colorDepth || 0,
            pixelRatio: window.devicePixelRatio || 1
        };
    }

    function getViewport() {
        var de = document.documentElement || {};
        return {
            viewportWidth: window.innerWidth || de.clientWidth || 0,
            viewportHeight: window.innerHeight || de.clientHeight || 0
        };
    }

    function getPerformance() {
        var p = window.performance;
        if (!p) {
            return {};
        }
        var navEntry = null;
        if (p.getEntriesByType) {
            var list = p.getEntriesByType('navigation');
            if (list && list.length) {
                navEntry = list[0];
            }
        }
        var t = p.timing;
        var out = {};
        if (navEntry) {
            if (navEntry.responseStart) {
                out.ttfbMs = Math.round(navEntry.responseStart);
            }
            if (navEntry.domContentLoadedEventEnd) {
                out.domContentLoadedMs = Math.round(navEntry.domContentLoadedEventEnd);
            }
            if (navEntry.loadEventEnd) {
                out.loadEventMs = Math.round(navEntry.loadEventEnd);
            }
        } else if (t && t.navigationStart) {
            if (t.responseStart) {
                out.ttfbMs = t.responseStart - t.navigationStart;
            }
            if (t.domContentLoadedEventEnd) {
                out.domContentLoadedMs = t.domContentLoadedEventEnd - t.navigationStart;
            }
            if (t.loadEventEnd) {
                out.loadEventMs = t.loadEventEnd - t.navigationStart;
            }
        }
        return out;
    }

    function collectPage() {
        var parsed = parseUrl(loc.href);
        return {
            url: sanitizeUrl(loc.href),
            path: parsed && parsed.pathname ? parsed.pathname : loc.pathname,
            title: document.title || '',
            hostname: loc.hostname || '',
            referrer: sanitizeUrl(document.referrer || ''),
            search: sanitizeQuery(loc.search || ''),
            protocol: loc.protocol || '',
            encoding: document.characterSet || document.charset || ''
        };
    }

    function collectAttribution() {
        var search = loc.search || '';
        var source = getQueryParam(search, 'utm_source');
        var medium = getQueryParam(search, 'utm_medium');
        var campaign = getQueryParam(search, 'utm_campaign');
        var content = getQueryParam(search, 'utm_content');
        var term = getQueryParam(search, 'utm_term');
        var marketing = state.consent && state.consent.marketing === true;
        var attr = {};
        var method = 'other';
        var clickIds = {};
        var hasClick = false;
        var i;

        if (marketing) {
            for (i = 0; i < CLICK_ID_KEYS.length; i++) {
                var val = getQueryParam(search, CLICK_ID_KEYS[i]);
                if (val) {
                    clickIds[CLICK_ID_KEYS[i]] = val;
                    hasClick = true;
                }
            }
        }

        if (hasClick && clickIds.gclid) {
            method = 'gclid_value';
            attr.source = source || 'google';
            attr.medium = medium || 'cpc';
        } else if (source || medium) {
            method = 'web_utm_parameters';
            attr.source = source || undefined;
            attr.medium = medium || undefined;
        } else if (document.referrer) {
            method = 'referrer';
            try {
                var ref = parseUrl(document.referrer);
                attr.source = ref && ref.hostname ? ref.hostname : 'referral';
            } catch (e) {
                attr.source = 'referral';
            }
            attr.medium = 'referral';
            attr.referrer = sanitizeUrl(document.referrer);
        } else {
            attr.source = 'direct';
            attr.medium = 'none';
            method = 'other';
        }

        if (marketing) {
            if (campaign) {
                attr.campaign = campaign;
            }
            if (content) {
                attr.content = content;
            }
            if (term) {
                attr.term = term;
            }
        }

        attr.attributionMethod = method;
        if (hasClick) {
            attr.clickIds = clickIds;
        }
        return attr;
    }

    function cacheStaticContext() {
        var ua = nav.userAgent || '';
        var parsed = parseUa(ua);
        var screenInfo = getScreen();
        var tz = '';
        try {
            tz = (Intl && Intl.DateTimeFormat)
                ? Intl.DateTimeFormat().resolvedOptions().timeZone
                : '';
        } catch (e) { /* ignore */ }

        state.contextCache = {
            browserName: parsed.browserName,
            osName: parsed.osName,
            osVersion: parsed.osVersion,
            language: nav.language || (nav.languages && nav.languages[0]) || '',
            locale: nav.language || '',
            timezone: tz,
            screenWidth: screenInfo.width,
            screenHeight: screenInfo.height,
            pixelRatio: screenInfo.pixelRatio,
            colorDepth: screenInfo.colorDepth,
            touch: ('ontouchstart' in window) || (nav.maxTouchPoints > 0),
            deviceMemoryGb: typeof nav.deviceMemory === 'number'
                ? nav.deviceMemory
                : undefined,
            hardwareConcurrency: typeof nav.hardwareConcurrency === 'number'
                ? nav.hardwareConcurrency
                : undefined,
            network: getNetwork()
        };
    }

    function buildContext() {
        if (!state.contextCache) {
            cacheStaticContext();
        }
        var c = state.contextCache;
        var vp = getViewport();
        var device = {
            deviceId: state.deviceId,
            browserName: c.browserName,
            osName: c.osName,
            osVersion: c.osVersion,
            platform: 'web',
            language: c.language,
            locale: c.locale,
            timezone: c.timezone || undefined,
            screenWidth: c.screenWidth,
            screenHeight: c.screenHeight,
            viewportWidth: vp.viewportWidth,
            viewportHeight: vp.viewportHeight,
            pixelRatio: c.pixelRatio,
            colorDepth: c.colorDepth,
            touch: c.touch
        };
        if (typeof c.deviceMemoryGb === 'number') {
            device.deviceMemoryGb = c.deviceMemoryGb;
        }
        if (typeof c.hardwareConcurrency === 'number') {
            device.hardwareConcurrency = c.hardwareConcurrency;
        }

        var ctx = {
            sdk: {
                version: SDK_VERSION,
                name: 'wcollect'
            },
            device: device
        };
        if (c.network && (c.network.effectiveType || c.network.downlink || c.network.rtt)) {
            ctx.network = c.network;
        }
        return ctx;
    }

    function buildUser() {
        var user = {
            anonymousId: state.anonymousId,
            userAgent: nav.userAgent || ''
        };
        if (state.userId && state.consent.analytics) {
            user.userId = state.userId;
        }
        if (state.userProperties && hasKeys(state.userProperties)) {
            user.properties = state.userProperties;
        }
        if (state.userData && hasKeys(state.userData)) {
            user.userData = state.userData;
        }
        return user;
    }

    function hasKeys(obj) {
        if (!obj) {
            return false;
        }
        var k;
        for (k in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, k) && obj[k] != null && obj[k] !== '') {
                return true;
            }
        }
        return false;
    }

    function prune(obj) {
        if (!obj || typeof obj !== 'object') {
            return obj;
        }
        if (Object.prototype.toString.call(obj) === '[object Array]') {
            return obj;
        }
        var out = {};
        var k;
        for (k in obj) {
            if (!Object.prototype.hasOwnProperty.call(obj, k)) {
                continue;
            }
            if (obj[k] === undefined) {
                continue;
            }
            out[k] = obj[k];
        }
        return out;
    }

    function bytesOf(str) {
        if (window.TextEncoder) {
            try {
                return new TextEncoder().encode(str).length;
            } catch (e) { /* fallback */ }
        }
        return unescape(encodeURIComponent(str)).length;
    }

    function buildBatch(events) {
        var page = collectPage();
        var perf = getPerformance();
        var defaultAttribution = null;
        var i;
        var enriched = [];
        for (i = 0; i < events.length; i++) {
            var ev = events[i];
            var props = ev.properties || {};
            var attribution;
            if (!props.url) {
                props.url = page.url;
            }
            if (!props.path) {
                props.path = page.path;
            }
            if (!props.title) {
                props.title = page.title;
            }
            if (!props.hostname) {
                props.hostname = page.hostname;
            }
            if (ev.name === 'page_view' && !props.referrer) {
                props.referrer = page.referrer;
            }
            if (ev.name === 'page_view' && hasKeys(perf)) {
                props.performance = perf;
            }
            if (ev.attribution) {
                attribution = prune(ev.attribution);
            } else {
                if (!defaultAttribution) {
                    defaultAttribution = prune(collectAttribution());
                }
                attribution = defaultAttribution;
            }
            enriched.push({
                id: ev.id || uuidV4(),
                timestamp: ev.timestamp || nowIso(),
                name: ev.name,
                category: ev.category || undefined,
                properties: prune(props),
                attribution: attribution
            });
        }

        return prune({
            projectId: state.projectId,
            sentAt: nowIso(),
            ingestionMethod: 'web_browser',
            user: buildUser(),
            context: buildContext(),
            consent: {
                analytics: !!state.consent.analytics,
                marketing: state.consent.marketing
            },
            events: enriched
        });
    }

    function sendPayload(payload) {
        var body;
        try {
            body = JSON.stringify(payload);
        } catch (e) {
            log('serialize failed', e);
            return false;
        }
        if (bytesOf(body) > BATCH_MAX_BYTES) {
            if (payload.events && payload.events.length > 1) {
                var mid = Math.ceil(payload.events.length / 2);
                var left = payload.events.slice(0, mid);
                var right = payload.events.slice(mid);
                sendPayload(buildBatch(left));
                return sendPayload(buildBatch(right));
            }
            log('payload too large, dropped');
            return false;
        }
        return transport(body);
    }

    function transport(body) {
        if (nav.sendBeacon) {
            try {
                var blob = new Blob([body], { type: TEXT_PLAIN });
                if (nav.sendBeacon(state.endpoint, blob)) {
                    log('sent via sendBeacon', body.length, 'bytes');
                    return true;
                }
            } catch (e) {
                log('sendBeacon failed', e);
            }
        }

        if (window.fetch) {
            try {
                window.fetch(state.endpoint, {
                    method: 'POST',
                    body: body,
                    keepalive: true,
                    mode: 'no-cors',
                    credentials: 'omit',
                    cache: 'no-store',
                    referrerPolicy: 'origin',
                    headers: { 'Content-Type': TEXT_PLAIN }
                });
                log('sent via fetch keepalive');
                return true;
            } catch (e) {
                log('fetch failed', e);
            }
        }

        try {
            var xhr = new XMLHttpRequest();
            xhr.open('POST', state.endpoint, true);
            xhr.withCredentials = false;
            xhr.setRequestHeader('Content-Type', TEXT_PLAIN);
            xhr.send(body);
            log('sent via xhr');
            return true;
        } catch (e) {
            log('xhr failed', e);
            return false;
        }
    }

    function scheduleFlush() {
        if (state.flushTimer) {
            return;
        }
        state.flushTimer = window.setTimeout(function () {
            state.flushTimer = null;
            flush();
        }, FLUSH_MS);
    }

    function flush(force) {
        if (state.flushTimer) {
            window.clearTimeout(state.flushTimer);
            state.flushTimer = null;
        }
        if (!state.queue.length) {
            return;
        }
        if (!state.consent.analytics && !force) {
            state.queue = [];
            return;
        }
        while (state.queue.length) {
            var chunk = state.queue.splice(0, BATCH_MAX_EVENTS);
            sendPayload(buildBatch(chunk));
        }
    }

    function enqueue(event) {
        if (!state.ready || isOptedOut() || !state.consent.analytics) {
            log('event dropped (not ready / opt-out / no consent)', event && event.name);
            return;
        }
        if (!event || !event.name) {
            return;
        }
        event.id = event.id || uuidV4();
        event.timestamp = event.timestamp || nowIso();
        state.queue.push(event);
        if (state.queue.length >= BATCH_MAX_EVENTS) {
            flush();
        } else {
            scheduleFlush();
        }
    }

    function track(name, options) {
        options = options || {};
        enqueue({
            name: String(name),
            category: options.category,
            properties: options.properties || {},
            attribution: options.attribution
        });
    }

    function trackPageView(extraProps) {
        var page = collectPage();
        if (page.url && page.url === state.lastTrackedUrl) {
            return;
        }
        state.lastTrackedUrl = page.url;
        state.pageEnteredAt = nowIso();
        state.pageEnteredMs = Date.now();
        var props = extraProps || {};
        track('page_view', {
            category: 'navigation',
            properties: props
        });
    }

    function trackPageHide() {
        var ts = Date.now();
        if (ts - state.lastHideSentAt < 400) {
            flush(true);
            return;
        }
        state.lastHideSentAt = ts;
        var dwell = ts - state.pageEnteredMs;
        track('page_hide', {
            category: 'navigation',
            properties: {
                dwellMs: dwell < 0 ? 0 : dwell,
                visibilityState: document.visibilityState || ''
            }
        });
        flush(true);
    }

    function onVisibility() {
        var hidden = document.hidden || document.visibilityState === 'hidden';
        if (hidden && !state.hidden) {
            state.hidden = true;
            trackPageHide();
        } else if (!hidden && state.hidden) {
            state.hidden = false;
            state.pageEnteredAt = nowIso();
            state.pageEnteredMs = Date.now();
        }
    }

    function wrapHistory() {
        if (!state.autoSpa || !window.history) {
            return;
        }
        var origPush = history.pushState;
        var origReplace = history.replaceState;
        if (typeof origPush === 'function') {
            history.pushState = function () {
                var ret = origPush.apply(this, arguments);
                onUrlChange();
                return ret;
            };
        }
        if (typeof origReplace === 'function') {
            history.replaceState = function () {
                var ret = origReplace.apply(this, arguments);
                onUrlChange();
                return ret;
            };
        }
        if (window.addEventListener) {
            window.addEventListener('popstate', onUrlChange, false);
        }
    }

    function onUrlChange() {
        window.setTimeout(function () {
            trackPageView();
        }, 0);
    }

    function bindLifecycle() {
        if (state.listenersBound || !document.addEventListener) {
            return;
        }
        state.listenersBound = true;
        document.addEventListener('visibilitychange', onVisibility, false);
        window.addEventListener('pagehide', function () {
            trackPageHide();
        }, false);
        window.addEventListener('pageshow', function (evt) {
            if (evt && evt.persisted) {
                state.hidden = false;
                state.lastTrackedUrl = '';
                trackPageView();
            }
        }, false);
        wrapHistory();
    }

    function normalizeEmail(value) {
        return String(value || '').replace(/^\s+|\s+$/g, '').toLowerCase();
    }

    function sha256Hex(message, done) {
        if (!message) {
            done(null);
            return;
        }
        if (!cryptoObj || !cryptoObj.subtle || !window.TextEncoder) {
            log('subtle crypto unavailable, PII not sent');
            done(null);
            return;
        }
        var buf;
        try {
            buf = new TextEncoder().encode(message);
        } catch (e) {
            done(null);
            return;
        }
        try {
            var digest = cryptoObj.subtle.digest('SHA-256', buf);
            if (!digest || typeof digest.then !== 'function') {
                done(null);
                return;
            }
            digest.then(function (hash) {
                var view = new Uint8Array(hash);
                var hex = '';
                var i;
                for (i = 0; i < view.length; i++) {
                    hex += ('0' + view[i].toString(16)).slice(-2);
                }
                done(hex);
            }, function () {
                done(null);
            });
        } catch (err) {
            done(null);
        }
    }

    function identify(userId, traits) {
        traits = traits || {};
        if (userId) {
            state.userId = String(userId);
        }
        if (traits.properties) {
            state.userProperties = traits.properties;
        }
        var pending = 0;
        var fields = [
            { key: 'emailSha', value: traits.email ? normalizeEmail(traits.email) : '' },
            { key: 'firstNameSha', value: traits.firstName ? String(traits.firstName).replace(/^\s+|\s+$/g, '').toLowerCase() : '' },
            { key: 'lastNameSha', value: traits.lastName ? String(traits.lastName).replace(/^\s+|\s+$/g, '').toLowerCase() : '' },
            { key: 'phoneSha', value: traits.phone ? String(traits.phone).replace(/\s+/g, '') : '' }
        ];
        var i;
        function onHash(key) {
            return function (hex) {
                if (hex) {
                    state.userData[key] = hex;
                }
                pending -= 1;
                if (pending <= 0) {
                    log('identify ready');
                }
            };
        }
        for (i = 0; i < fields.length; i++) {
            if (fields[i].value) {
                pending += 1;
                sha256Hex(fields[i].value, onHash(fields[i].key));
            }
        }
    }

    function logout() {
        state.userId = null;
        state.userData = {};
        state.userProperties = {};
    }

    function setConsent(consent) {
        consent = consent || {};
        if (typeof consent.analytics === 'boolean') {
            state.consent.analytics = consent.analytics;
        }
        if (consent.marketing === true || consent.marketing === false || consent.marketing === null) {
            state.consent.marketing = consent.marketing;
        }
        if (!state.consent.analytics) {
            state.queue = [];
        }
    }

    function resolveEndpoint(url) {
        if (!url) {
            return COLLECT_URL;
        }
        var parsed = parseUrl(url);
        if (!parsed || parsed.protocol !== 'https:' ||
                parsed.hostname !== ALLOWED_HOST) {
            log('endpoint rejected, fallback to default', url);
            return COLLECT_URL;
        }
        return parsed.protocol + '//' + parsed.host +
            (parsed.pathname || DEFAULT_PATH);
    }

    function readScriptConfig() {
        var script = document.currentScript;
        if (!script && document.querySelector) {
            script = document.querySelector('script[data-project-id][src*="wcollect"]');
        }
        if (!script || !script.getAttribute) {
            return {};
        }
        var autoSpaAttr = script.getAttribute('data-auto-spa');
        return {
            projectId: script.getAttribute('data-project-id') || '',
            endpoint: script.getAttribute('data-endpoint') || '',
            debug: script.getAttribute('data-debug') === 'true',
            autoPageView: script.getAttribute('data-auto-page-view') !== 'false',
            autoSpa: autoSpaAttr === null ? undefined : autoSpaAttr !== 'false'
        };
    }

    function init(options) {
        options = options || {};
        var fromScript = readScriptConfig();
        var projectId = options.projectId || fromScript.projectId || state.projectId;
        if (!projectId || !/^[a-zA-Z0-9_.:-]{1,80}$/.test(projectId)) {
            log('init aborted: projectId invalide');
            return api;
        }
        if (isOptedOut()) {
            log('opt-out actif, collecte ignorée');
            state.ready = false;
            return api;
        }

        state.projectId = projectId;
        state.debug = !!(options.debug || fromScript.debug);
        state.endpoint = resolveEndpoint(options.endpoint || fromScript.endpoint);
        if (typeof options.autoPageView === 'boolean') {
            state.autoPageView = options.autoPageView;
        } else if (typeof fromScript.autoPageView === 'boolean') {
            state.autoPageView = fromScript.autoPageView;
        }
        if (typeof options.autoSpa === 'boolean') {
            state.autoSpa = options.autoSpa;
        } else if (typeof fromScript.autoSpa === 'boolean') {
            state.autoSpa = fromScript.autoSpa;
        }
        if (options.consent) {
            setConsent(options.consent);
        }
        if (options.userId) {
            identify(options.userId, options.traits || {});
        }

        state.anonymousId = getOrCreateAnonymousId();
        state.deviceId = state.anonymousId;
        cacheStaticContext();
        state.ready = true;
        bindLifecycle();

        if (state.autoPageView) {
            trackPageView();
        }
        log('init', state.projectId, state.anonymousId);
        return api;
    }

    function optOut() {
        setOptOut(true);
        state.queue = [];
        state.ready = false;
        logout();
    }

    function optIn() {
        setOptOut(false);
        if (state.projectId) {
            init({
                projectId: state.projectId,
                debug: state.debug,
                endpoint: state.endpoint
            });
        }
    }

    function drainQueue(queue) {
        if (!queue || !queue.length) {
            return;
        }
        var i;
        for (i = 0; i < queue.length; i++) {
            applyCommand(queue[i]);
        }
    }

    function applyCommand(args) {
        if (!args) {
            return;
        }
        var list = args;
        if (!list.length && typeof args === 'object' && !args[0]) {
            return;
        }
        var method = list[0];
        var rest = Array.prototype.slice.call(list, 1);
        if (method === 'init') {
            init(rest[0] || {});
        } else if (typeof api[method] === 'function') {
            api[method].apply(api, rest);
        }
    }

    var api = function () {
        applyCommand(arguments);
    };
    api.init = init;
    api.track = track;
    api.page = trackPageView;
    api.identify = identify;
    api.logout = logout;
    api.setConsent = setConsent;
    api.flush = function () { flush(true); };
    api.optOut = optOut;
    api.optIn = optIn;
    api.getAnonymousId = function () { return state.anonymousId; };
    api.version = SDK_VERSION;

    var previous = window.WCollect;
    var pending = (previous && previous.q) ? previous.q.slice() : [];
    window.WCollect = api;

    var scriptCfg = readScriptConfig();
    if (scriptCfg.projectId && !state.ready) {
        init(scriptCfg);
    }
    drainQueue(pending);

})(window, document);
