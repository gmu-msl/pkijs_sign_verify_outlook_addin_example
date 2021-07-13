import { Convert } from "pvtsutils"; 
import * as x509 from "@peculiar/x509";

x509.PemConverter

/* x509.PemConverter */
export class PemConverter {
    CertificateTag: string;
    CertificateRequestTag: string;
    PublicKeyTag: string;
    PrivateKeyTag: string;
    
    constructor() {
        this.CertificateTag = "CERTIFICATE";
        this.CertificateRequestTag = "CERTIFICATE REQUEST";
        this.PublicKeyTag = "PUBLIC KEY";
        this.PrivateKeyTag = "PRIVATE KEY";
    }
    static isPem(data) {
        return typeof data === "string"
            && /-{5}BEGIN [A-Z0-9 ]+-{5}([a-zA-Z0-9=+/\n\r]+)-{5}END [A-Z0-9 ]+-{5}/g.test(data);
    }
    static decode(pem) {
        const pattern = /-{5}BEGIN [A-Z0-9 ]+-{5}([a-zA-Z0-9=+/\n\r]+)-{5}END [A-Z0-9 ]+-{5}/g;
        const res = [];
        let matches = null;
        while (matches = pattern.exec(pem)) {
            const base64 = matches[1]
                .replace(/\r/g, "")
                .replace(/\n/g, "");
            res.push(Convert.FromBase64(base64));
        }
        return res;
    }
    static encode(rawData, tag) {
        if (Array.isArray(rawData)) {
            const raws = new Array();
            rawData.forEach(element => {
                raws.push(this.encodeBuffer(element, tag));
            });
            return raws.join("\n");
        }
        else {
            return this.encodeBuffer(rawData, tag);
        }
    }
    static encodeBuffer(rawData, tag) {
        const base64 = Convert.ToBase64(rawData);
        let sliced;
        let offset = 0;
        const rows = Array();
        while (offset < base64.length) {
            if (base64.length - offset < 64) {
                sliced = base64.substring(offset);
            }
            else {
                sliced = base64.substring(offset, offset + 64);
                offset += 64;
            }
            if (sliced.length !== 0) {
                rows.push(sliced);
                if (sliced.length < 64) {
                    break;
                }
            }
            else {
                break;
            }
        }
        const upperCaseTag = tag.toLocaleUpperCase();
        return `-----BEGIN ${upperCaseTag}-----\n${rows.join("\n")}\n-----END ${upperCaseTag}-----`;
    }
}

export function decodeHtml(html: string): string {
    var txt = document.createElement("textarea");
    txt.innerHTML = html;
    return txt.value;
}

export function encodeHtml(str: string): string {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}