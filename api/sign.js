// Conteúdo para o arquivo: api/sign.js (Retorna o body completo para o n8n)
const crypto = require('crypto');

// Função de assinatura AWS Signature V4
function getSignature(requestBody, aws_access_key_id, aws_secret_access_key, region, service) {
    const method = 'POST';
    const host = 'webservices.amazon.com.br';
    const canonicalUri = '/paapi5/getitems';
    const amzTarget = 'com.amazon.paapi5.v1.ProductAdvertisingAPIv1.GetItems';

    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = now.toISOString().slice(0, 10).replace(/-/g, '');

    const canonicalQuerystring = '';
    const signedHeaders = 'host;x-amz-date;x-amz-target';

    const canonicalHeaders = `host:${host}\n` +
                             `x-amz-date:${amzDate}\n` +
                             `x-amz-target:${amzTarget}\n`;

    const payloadHash = crypto.createHash('sha256').update(JSON.stringify(requestBody)).digest('hex');
    const canonicalRequest = `${method}\n${canonicalUri}\n${canonicalQuerystring}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
    const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${crypto.createHash('sha256').update(canonicalRequest).digest('hex')}`;

    const getSignatureKey = (key, dateStamp, regionName, serviceName) => {
        const kDate = crypto.createHmac('sha256', 'AWS4' + key).update(dateStamp).digest();
        const kRegion = crypto.createHmac('sha256', kDate).update(regionName).digest();
        const kService = crypto.createHmac('sha256', kRegion).update(serviceName).digest();
        return crypto.createHmac('sha256', kService).update('aws4_request').digest();
    };

    const signingKey = getSignatureKey(aws_secret_access_key, dateStamp, region, service);
    const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');

    const authorizationHeader = `AWS4-HMAC-SHA256 Credential=${aws_access_key_id}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return {
        'host': host,
        'x-amz-date': amzDate,
        'x-amz-target': amzTarget,
        'Authorization': authorizationHeader,
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Encoding': 'amz-1.0'
    };
}

export default function handler(request, response) {
    const { AUTH_TOKEN, AMAZON_ACCESS_KEY, AMAZON_SECRET_KEY } = process.env;

    const authToken = request.headers['x-auth-token'];
    if (authToken !== AUTH_TOKEN) {
        return response.status(401).json({ error: 'Unauthorized' });
    }

    const { asin } = request.body;
    if (!asin) {
        return response.status(400).json({ error: 'Bad Request: Missing asin in the request body.' });
    }

    // Payload com recursos ESSENCIAIS e priorizando OffersV2 para preço promocional
    const amazonPayloadForRequest = {
        "ItemIds": [asin],
        "Resources": [
            "ItemInfo.Title",
            "Images.Primary.Large",
            "CustomerReviews.Summary",               // Para avaliações e contagem
            "Offers.Listings.DeliveryInfo.IsPrimeEligible", // Frete Prime
            "Offers.Listings.DeliveryInfo.IsFreeShippingEligible", // Frete Grátis
            
            // Adicionando explicitamente OffersV2 para o preço promocional
            "OffersV2.Listings.Price",
            "OffersV2.Listings.DealDetails"         // Para informações como "Oferta Prime Day"
        ],
        "PartnerTag": "luizapinhei00-20",
        "PartnerType": "Associates",
        "Marketplace": "www.amazon.com.br",
        "Operation": "GetItems"
    };

    const region = 'us-east-1';
    const service = 'ProductAdvertisingAPI';
    const authHeaders = getSignature(amazonPayloadForRequest, AMAZON_ACCESS_KEY, AMAZON_SECRET_KEY, region, service);

    response.status(200).json({
        headers: authHeaders,
        body: amazonPayloadForRequest, // Este body é o que será enviado para a Amazon
        endpoint: `https://${authHeaders.host}/paapi5/getitems`
    });
}
