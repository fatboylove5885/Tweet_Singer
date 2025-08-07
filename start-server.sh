start-server.sh
#!/bin/bash

echo "🔧 Installing dependencies..."
npm install

echo "🚀 Starting the OAuth Signer Server..."
node index.js
