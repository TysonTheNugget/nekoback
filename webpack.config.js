const path = require('path');

module.exports = {
  entry: './entry.js',
  output: {
    filename: 'sats-connect-bundle.js',
    path: path.resolve(__dirname, 'static'),
  },
  mode: 'production',
  resolve: {
    // Add polyfills here if a dependency complains about Node builtins.
    fallback: {
      crypto: false,
    },
  },
};
