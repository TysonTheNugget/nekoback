// entry.js
import { getAddress, createInscription } from '@sats-connect/core';

(function attachSatsConnect() {
  console.log('[SatsConnect] Initializing...');

  function resolveProvider() {
    const provider = window.BitcoinProvider || window.btc || window.unisat || window.XverseProviders?.BitcoinProvider;
    if (!provider || typeof provider.request !== 'function') {
      console.error('[SatsConnect] No BitcoinProvider.request() found.');
      throw new Error('No BitcoinProvider.request() found. Is your wallet installed/unlocked?');
    }
    console.log('[SatsConnect] Provider found:', provider);
    return provider;
  }

  async function request(method, params) {
    const provider = resolveProvider();
    console.log('[SatsConnect] Requesting:', method, params);
    return provider.request(method, params);
  }

  async function wrappedGetAddress(opts = {}) {
    return getAddress({ getProvider: resolveProvider, ...opts });
  }

  async function wrappedCreateInscription(opts = {}) {
    return createInscription({ getProvider: resolveProvider, ...opts });
  }

  // Explicitly set window.SatsConnect
  window.SatsConnect = {
    request,
    getAddress: wrappedGetAddress,
    createInscription: wrappedCreateInscription,
  };
  console.log('[SatsConnect] Attached to window:', window.SatsConnect);
})();