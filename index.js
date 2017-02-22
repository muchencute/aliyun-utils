const URL = require('url');
const crypto = require('crypto');

class AliyunUtils {

    /**
     * 签名
     * @param url URL
     * @param appSecret AppSecret
     * @returns {string} 签名结果
     */
    static signature(url, appSecret) {
        let query = URL.parse(url).query;
        let params = query.split('&');
        for (let param of params) {
            let components = param.split('=');
            param = `${encodeURIComponent(components[0])}=${encodeURIComponent(components[1])}`;
        }
        params.sort();
        let stringToSign = `GET&%2F&${encodeURIComponent(params.join('&'))}`;
        return crypto.createHmac('sha1', appSecret).update(stringToSign).digest('base64');
    }

}

module.exports = AliyunUtils;