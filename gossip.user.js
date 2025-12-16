// ==UserScript==
// @name         Госуслуги - Автоматический вход
// @namespace    http://tampermonkey.net/
// @version      1.2
// @description  Автоматический вход на портал Госуслуг
// @author       suprohub
// @match        https://esia.gosuslugi.ru/*
// @match        https://gosuslugi.ru/*
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_registerMenuCommand
// @license      MIT
// ==/UserScript==

(function() {
    'use strict';

    const CONFIG = {
        password: GM_getValue('password', ''),
        totpUrl: GM_getValue('totpUrl', ''),
        debug: true
    };

    class TOTPGenerator {
        static base32ToBytes(base32) {
            const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            const cleaned = base32.replace(/=+$/, '').toUpperCase();
            let bytes = [];

            for (let i = 0; i < cleaned.length; i += 8) {
                let chunk = cleaned.slice(i, i + 8);
                let binary = '';

                for (let j = 0; j < chunk.length; j++) {
                    const val = alphabet.indexOf(chunk[j]);
                    binary += val.toString(2).padStart(5, '0');
                }

                for (let j = 0; j < binary.length; j += 8) {
                    const byte = binary.slice(j, j + 8);
                    if (byte.length === 8) bytes.push(parseInt(byte, 2));
                }
            }

            return new Uint8Array(bytes);
        }

        static async generateTOTP(secret) {
            try {
                if (secret.startsWith('otpauth://')) {
                    const url = new URL(secret);
                    secret = url.searchParams.get('secret') || secret;
                }

                const keyBytes = this.base32ToBytes(secret);
                const time = Math.floor(Date.now() / 1000);
                let counterValue = Math.floor(time / 30);

                const counterBytes = new Uint8Array(8);
                for (let i = 7; i >= 0; i--) {
                    counterBytes[i] = counterValue & 0xff;
                    counterValue = Math.floor(counterValue / 256);
                }

                const key = await crypto.subtle.importKey(
                    'raw',
                    keyBytes,
                    { name: 'HMAC', hash: { name: 'SHA-1' } },
                    false,
                    ['sign']
                );

                const hmac = await crypto.subtle.sign('HMAC', key, counterBytes);
                const hmacBytes = new Uint8Array(hmac);
                const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;

                const code = (
                    ((hmacBytes[offset] & 0x7f) << 24) |
                    ((hmacBytes[offset + 1] & 0xff) << 16) |
                    ((hmacBytes[offset + 2] & 0xff) << 8) |
                    (hmacBytes[offset + 3] & 0xff)
                ) % 1000000;

                return code.toString().padStart(6, '0');
            } catch (error) {
                console.error('TOTP error:', error);
                return null;
            }
        }
    }

    const Utils = {
        log: (...args) => CONFIG.debug && console.log('[Госуслуги]', ...args),

        wait: (ms) => new Promise(resolve => setTimeout(resolve, ms)),

        waitForElement: (selector, timeout = 10000) => new Promise((resolve, reject) => {
            const start = Date.now();
            const check = () => {
                const el = document.querySelector(selector);
                if (el) return resolve(el);
                if (Date.now() - start > timeout) return reject(new Error(`Element ${selector} not found`));
                setTimeout(check, 200);
            };
            check();
        }),

        waitForElements: (selector, count, timeout = 10000) => new Promise((resolve, reject) => {
            const start = Date.now();
            const check = () => {
                const els = document.querySelectorAll(selector);
                if (els.length >= count) return resolve(Array.from(els));
                if (Date.now() - start > timeout) return reject(new Error(`Elements ${selector} not found`));
                setTimeout(check, 200);
            };
            check();
        }),

        isPasswordPage: () => !!document.querySelector('input#password.plain-input.no-label'),

        isCodePage: () => !!document.querySelector('esia-code-input div.code-input'),

        showNotification: (message, type = 'info') => {
            const div = document.createElement('div');
            div.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 15px;
                background: ${type === 'error' ? '#f44336' : '#4CAF50'};
                color: white;
                border-radius: 5px;
                z-index: 999999;
                font-family: Arial, sans-serif;
                font-size: 14px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            `;
            div.textContent = `[Госуслуги] ${message}`;
            document.body.appendChild(div);
            setTimeout(() => div.remove(), 5000);
        }
    };

    class GosuslugiAutoLogin {
        constructor() {
            this.attempts = 0;
            this.maxAttempts = 3;
        }

        async init() {
            await Utils.wait(1000);

            if (Utils.isPasswordPage()) {
                await this.handlePasswordPage();
            } else if (Utils.isCodePage()) {
                await this.handleCodePage();
            }
        }

        async handlePasswordPage() {
            try {
                if (!CONFIG.password) {
                    Utils.showNotification('Настройте пароль в меню скрипта', 'error');
                    return;
                }

                const passwordField = await Utils.waitForElement('input#password.plain-input.no-label');
                const submitButton = await Utils.waitForElement('button.plain-button.plain-button_wide');

                passwordField.value = CONFIG.password;
                passwordField.dispatchEvent(new Event('input', { bubbles: true }));
                passwordField.dispatchEvent(new Event('change', { bubbles: true }));

                await Utils.wait(500);
                submitButton.click();
                await Utils.wait(3000);

            } catch (error) {
                Utils.log('Password page error:', error);
            }
        }

        async handleCodePage() {
            try {
                if (!CONFIG.totpUrl) {
                    Utils.showNotification('Настройте TOTP в меню скрипта', 'error');
                    return;
                }

                const code = await TOTPGenerator.generateTOTP(CONFIG.totpUrl);
                if (!code) {
                    Utils.showNotification('Ошибка генерации кода', 'error');
                    return;
                }

                Utils.log(`Code: ${code}`);
                const inputs = await Utils.waitForElements('input[type="tel"], input[type="text"], input[type="number"]', 6);
                await this.enterCode(inputs, code);

            } catch (error) {
                Utils.log('Code page error:', error);
                Utils.showNotification(`Ошибка: ${error.message}`, 'error');
            }
        }

        async enterCode(inputs, code) {
            inputs[0].focus();

            for (let i = 0; i < Math.min(6, inputs.length); i++) {
                const input = inputs[i];
                const digit = code[i];

                input.value = '';
                input.dispatchEvent(new Event('input', { bubbles: true }));
                input.dispatchEvent(new Event('change', { bubbles: true }));

                await Utils.wait(50);

                input.value = digit;
                input.dispatchEvent(new Event('input', { bubbles: true }));
                input.dispatchEvent(new Event('change', { bubbles: true }));

                input.dispatchEvent(new KeyboardEvent('keydown', { key: digit, code: `Digit${digit}`, keyCode: digit.charCodeAt(0), bubbles: true }));
                input.dispatchEvent(new KeyboardEvent('keyup', { key: digit, code: `Digit${digit}`, keyCode: digit.charCodeAt(0), bubbles: true }));

                if (i < 5 && inputs[i + 1]) {
                    inputs[i + 1].focus();
                }

                await Utils.wait(100);
            }
        }
    }

    function registerSettingsMenu() {
        GM_registerMenuCommand('⚙️ Настроить пароль', () => {
            const password = prompt('Введите пароль:');
            if (password !== null) {
                GM_setValue('password', password);
                CONFIG.password = password;
                alert('Пароль сохранен');
            }
        });

        GM_registerMenuCommand('🔑 Настроить TOTP URL', () => {
            const totpUrl = prompt('Введите TOTP URL (otpauth://...):');
            if (totpUrl !== null) {
                GM_setValue('totpUrl', totpUrl);
                CONFIG.totpUrl = totpUrl;
                alert('TOTP URL сохранен');
            }
        });

        GM_registerMenuCommand('🔢 Проверить TOTP', async () => {
            if (!CONFIG.totpUrl) {
                alert('Сначала настройте TOTP URL');
                return;
            }

            const code = await TOTPGenerator.generateTOTP(CONFIG.totpUrl);
            if (code) {
                const secondsLeft = 30 - (Math.floor(Date.now() / 1000) % 30);
                alert(`Код: ${code}\n\nДействителен: ${secondsLeft} секунд`);
            } else {
                alert('Ошибка генерации кода');
            }
        });

        GM_registerMenuCommand('📋 Информация', () => {
            alert(`Госуслуги - Автоматический вход v1.2\n\nПароль: ${CONFIG.password ? 'настроен' : 'не настроен'}\nTOTP: ${CONFIG.totpUrl ? 'настроен' : 'не настроен'}`);
        });
    }

    async function main() {
        if (!window.location.href.includes('esia.gosuslugi.ru') && !window.location.href.includes('gosuslugi.ru')) return;

        registerSettingsMenu();
        const autoLogin = new GosuslugiAutoLogin();
        autoLogin.init();

        let lastUrl = window.location.href;
        setInterval(() => {
            if (window.location.href !== lastUrl) {
                lastUrl = window.location.href;
                autoLogin.init();
            }
        }, 1000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', main);
    } else {
        main();
    }

})();
