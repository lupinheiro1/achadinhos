// Conteúdo CORRETO e FINAL para o arquivo: api/sign.js
const crypto = require('crypto');

// Função de assinatura AWS Signature V4, agora corrigida para o Host do Brasil
function getSignature(requestBody, aws_access_key_id, aws_secret_access_key, region, service) {
    const method = 'POST';
    // PONTO 1: Host correto para o Brasil
    const host = 'webservices.amazon.com.br';
    const canonicalUri = '/paapi5/getitems';
    const amzTarget = 'com.amazon.paapi5.v1.ProductAdvertisingAPIv1.GetItems'; // Note: O target é v1, não v5, conforme seu header.

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
        'host': host, // Adicionado para garantir que o n8n use o host correto
        'x-amz-date': amzDate,
        'x-amz-target': amzTarget,
        'Authorization': authorizationHeader,
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Encoding': 'amz-1.0'
    };
}

export default function handler(request, response) {
    // Usamos as chaves da Vercel para segurança
    const { AUTH_TOKEN, AMAZON_ACCESS_KEY, AMAZON_SECRET_KEY } = process.env;

    const authToken = request.headers['x-auth-token'];
    if (authToken !== AUTH_TOKEN) {
        return response.status(401).json({ error: 'Unauthorized' });
    }

    // A única informação que precisamos do n8n é o ASIN do produto
    const { asin } = request.body;
    if (!asin) {
        return response.status(400).json({ error: 'Bad Request: Missing asin in the request body.' });
    }

    // PONTO 2: Montar o payload EXATAMENTE como no Scratchpad, com todos os Resources.
    const amazonPayload = {
        "ItemIds": [asin],
        "Resources": [
            "BrowseNodeInfo.BrowseNodes", "BrowseNodeInfo.BrowseNodes.Ancestor", "BrowseNodeInfo.BrowseNodes.SalesRank",
            "BrowseNodeInfo.WebsiteSalesRank", "CustomerReviews.Count", "CustomerReviews.StarRating", "Images.Primary.Small",
            "Images.Primary.Medium", "Images.Primary.Large", "Images.Primary.HighRes", "Images.Variants.Small", "Images.Variants.Medium",
            "Images.Variants.Large", "Images.Variants.HighRes", "ItemInfo.ByLineInfo", "ItemInfo.ContentInfo", "ItemInfo.ContentRating",
            "ItemInfo.Classifications", "ItemInfo.ExternalIds", "ItemInfo.Features", "ItemInfo.ManufactureInfo", "ItemInfo.ProductInfo",
            "ItemInfo.TechnicalInfo", "ItemInfo.Title", "ItemInfo.TradeInInfo", "Offers.Listings.Availability.MaxOrderQuantity",
            "Offers.Listings.Availability.Message", "Offers.Listings.Availability.MinOrderQuantity", "Offers.Listings.Availability.Type",
            "Offers.Listings.Condition", "Offers.Listings.Condition.ConditionNote", "Offers.Listings.Condition.SubCondition",
            "Offers.Listings.DeliveryInfo.IsAmazonFulfilled", "Offers.Listings.DeliveryInfo.IsFreeShippingEligible",
            "Offers.Listings.DeliveryInfo.IsPrimeEligible", "Offers.Listings.DeliveryInfo.ShippingCharges",
            "Offers.Listings.IsBuyBoxWinner", "Offers.Listings.LoyaltyPoints.Points", "Offers.Listings.MerchantInfo",
            "Offers.Listings.Price", "Offers.Listings.ProgramEligibility.IsPrimeExclusive", "Offers.Listings.ProgramEligibility.IsPrimePantry",
            "Offers.Listings.Promotions", "Offers.Listings.SavingBasis", "Offers.Summaries.HighestPrice", "Offers.Summaries.LowestPrice",
            "Offers.Summaries.OfferCount", "ParentASIN", "RentalOffers.Listings.Availability.MaxOrderQuantity",
            "RentalOffers.Listings.Availability.Message", "RentalOffers.Listings.Availability.MinOrderQuantity",
            "RentalOffers.Listings.Availability.Type", "RentalOffers.Listings.BasePrice", "RentalOffers.Listings.Condition",
            "RentalOffers.Listings.Condition.ConditionNote", "RentalOffers.Listings.Condition.SubCondition",
            "RentalOffers.Listings.DeliveryInfo.IsAmazonFulfilled", "RentalOffers.Listings.DeliveryInfo.IsFreeShippingEligible",
            "RentalOffers.Listings.DeliveryInfo.IsPrimeEligible", "RentalOffers.Listings.DeliveryInfo.ShippingCharges",
            "RentalOffers.Listings.MerchantInfo",
            // Novos recursos OffersV2 adicionados
            "OffersV2.Listings.Availability",
            "OffersV2.Listings.Condition",
            "OffersV2.Listings.DealDetails",
            "OffersV2.Listings.IsBuyBoxWinner",
            "OffersV2.Listings.LoyaltyPoints",
            "OffersV2.Listings.MerchantInfo",
            "OffersV2.Listings.Price",
            "OffersV2.Listings.Type"
        ],
        "PartnerTag": "luizapinhei00-20",      // PONTO 3: PartnerTag fixo e correto
        "PartnerType": "Associates",
        "Marketplace": "www.amazon.com.br", // PONTO 4: Marketplace fixo e correto para o Brasil
        "Operation": "GetItems"
    };

    // A região para o Brasil continua sendo us-east-1
    const region = 'us-east-1';
    const service = 'ProductAdvertisingAPI';
    const authHeaders = getSignature(amazonPayload, AMAZON_ACCESS_KEY, AMAZON_SECRET_KEY, region, service);

    // Retornar tudo que o n8n precisa
    response.status(200).json({
        headers: authHeaders,
        body: amazonPayload,
        // Endpoint agora usa o Host correto retornado nos headers
        endpoint: `https://${authHeaders.host}/paapi5/getitems`
    });
}
