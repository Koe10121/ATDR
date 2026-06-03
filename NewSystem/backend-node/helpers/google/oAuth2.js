const instance = require('axios');

// instance.defaults.baseURL = 'https://www.googleapis.com';
//
// instance.defaults.headers = {
//     "Content-Type": "application/json"
// }


const googleAuthAPI = instance.create({
    baseURL: 'https://www.googleapis.com',
    headers: { 'Content-Type': 'application/json' }
});

const googleMapsAPI = instance.create({
    baseURL: 'https://maps.googleapis.com',
    headers: { 'Content-Type': 'application/json' }
});

exports.onQuery = async function (request, response, next) {

    var config = {};

    var params = {};
    params.alt = "json";
    params.access_token = request.body.token
    config.params = params;

    var response = await googleAuthAPI.get("/oauth2/v3/userinfo",config)
    console.log(response)
};

exports.onDistance = async function (request, response, next) {
    const { origin, destinations, apiKey, language } = request.body;

    if (!origin || !destinations || !Array.isArray(destinations) || destinations.length === 0 || !apiKey) {
        return response.status(400).json({ error: "Missing origin, destinations, or apiKey" });
    }

    try {
        const destinationStr = destinations.map(d => `${d.lat},${d.lng}`).join('|');
        const originStr = `${origin.lat},${origin.lng}`;

        const config = {
            params: {
                origins: originStr,
                destinations: destinationStr,
                key: apiKey,
                language: language || 'en'   // กำหนดค่า default เป็นอังกฤษ
            }
        };

        const res = await googleMapsAPI.get('/maps/api/distancematrix/json', config);

        console.log('Google Response:', res.data); // <-- เพิ่มบรรทัดนี้

        const result = res.data.rows[0].elements.map((element, index) => ({
            from: res.data.origin_addresses[0],
            to: res.data.destination_addresses[index],
            distance: element.distance?.text || 'N/A',
            duration: element.duration?.text || 'N/A',
            status: element.status
        }));

        // response.json({ origin: res.data.origin_addresses[0], results: result });

        return response.status(200).json({ origin: res.data.origin_addresses[0], results: result });

    } catch (err) {
        // ลองดูข้อมูล error ให้ละเอียด
        console.error("Distance error message:", err.message);
        if (err.response) {
            console.error("Status code:", err.response.status);
            console.error("Response data:", err.response.data);
        } else {
            console.error("No response from API.");
        }
        response.status(500).json({ error: "Failed to fetch distance", details: err.message });
    }
};

