const http = require('http');

const testCors = (origin, description) => {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: 3000,
      path: '/api/quotes',
      method: 'OPTIONS',
      headers: {
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type'
      }
    };

    if (origin) {
      options.headers.Origin = origin;
    }

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        console.log(`\n🧪 ${description}`);
        console.log(`Origin: ${origin || 'null'}`);
        console.log(`Status: ${res.statusCode}`);
        console.log(`Access-Control-Allow-Origin: ${res.headers['access-control-allow-origin'] || 'not set'}`);
        console.log(`Access-Control-Allow-Methods: ${res.headers['access-control-allow-methods'] || 'not set'}`);
        resolve();
      });
    });

    req.on('error', (error) => {
      console.log(`\n❌ ${description}`);
      console.log(`Error: ${error.message}`);
      resolve();
    });

    req.end();
  });
};

const runTests = async () => {
  console.log('🚀 Testing CORS Configuration...');
  
  await testCors('https://banddcleaning.com.au', 'Valid Production Origin');
  await testCors('http://localhost:3000', 'Development Origin');
  await testCors('https://evil-site.com', 'Invalid Origin');
  await testCors(null, 'No Origin (Mobile App)');
  
  console.log('\n✅ CORS testing completed!');
};

runTests().catch(console.error);