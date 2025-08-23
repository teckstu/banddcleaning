const axios = require('axios');

const testCors = async () => {
  const baseUrl = process.env.NODE_ENV === 'production' 
    ? 'https://your-domain.com' 
    : 'http://localhost:3000';

  const tests = [
    {
      name: 'Valid Origin Test',
      origin: 'https://banddcleaning.com.au',
      shouldPass: true
    },
    {
      name: 'Invalid Origin Test',
      origin: 'https://malicious-site.com',
      shouldPass: false
    },
    {
      name: 'No Origin Test (mobile app)',
      origin: null,
      shouldPass: true
    },
    {
      name: 'Localhost Test (development only)',
      origin: 'http://localhost:3000',
      shouldPass: process.env.NODE_ENV !== 'production'
    }
  ];

  console.log('🧪 Testing CORS Configuration...\n');

  for (const test of tests) {
    try {
      const headers = {};
      if (test.origin) {
        headers.Origin = test.origin;
      }

      const response = await axios.options(`${baseUrl}/api/quotes`, {
        headers,
        timeout: 5000
      });

      const accessControlOrigin = response.headers['access-control-allow-origin'];
      const passed = test.shouldPass ? !!accessControlOrigin : !accessControlOrigin;

      console.log(`${passed ? '✅' : '❌'} ${test.name}`);
      console.log(`   Origin: ${test.origin || 'null'}`);
      console.log(`   Response: ${accessControlOrigin || 'blocked'}`);
      console.log(`   Expected: ${test.shouldPass ? 'allowed' : 'blocked'}\n`);

    } catch (error) {
      const passed = !test.shouldPass;
      console.log(`${passed ? '✅' : '❌'} ${test.name}`);
      console.log(`   Origin: ${test.origin || 'null'}`);
      console.log(`   Error: ${error.message}`);
      console.log(`   Expected: ${test.shouldPass ? 'allowed' : 'blocked'}\n`);
    }
  }
};

testCors().catch(console.error);