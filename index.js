const URL = require('url');
const crypto = require('crypto');

class AliyunUtils {

    /**
     * URL 签名
     * @param url URL
     * @param appSecret AppSecret
     * @returns {string} 签名结果
     */
    static signatureURL(url, appSecret) {
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

    /**
     * 头部签名
     * @param bucket
     * @param options
     * @param appSecret
     */
    static signatureHeaders(bucket, options, appSecret) {
        options.method = options.method || 'GET';
        options.headers['Content-MD5'] = options.headers['Content-MD5'] || '';
        options.headers['Content-Type'] = options.headers['Content-Type'] || '';
        options.headers['Date'] = options.headers['Date'] || new Date().toUTCString();

        let ossHeader = '';
        let headers = [];

        Object.keys(options.headers).forEach((it) => {
            if (/x-oss-/i.test(it)) {
                headers.push(it);
            }
        });

        headers = headers.sort(function (a, b) {
            let lA = a.toLowerCase();
            let lB = b.toLowerCase();
            return lA.localeCompare(lB);
        });

        headers.forEach((it) => {
            ossHeader += `${it.toLowerCase()}:${options.headers[it]}\n`;
        });

        let resources = `/${bucket}${decodeURI(options.path)}`;
        let content = `${options.method}\n${options.headers['Content-MD5']}\n${options.headers['Content-Type']}\n${options.headers['Date']}\n${ossHeader}${resources}`;
        return crypto.createHmac('sha1', appSecret).update(content).digest('base64');
    }

}

module.exports = AliyunUtils;