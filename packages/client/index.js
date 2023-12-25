import nacl from "tweetnacl-sealed-box";

class SupportClient {

    constructor(url, userKey, fetch, crypto, agent) {
        this.global = typeof self !== 'undefined' ? self : (typeof window !== 'undefined' ? window : '')
        this.url = url;
        this.userKey = userKey;
        this.fetch = fetch || this.global.fetch.bind(this.global);
        // this is for SSL certificate expired
        this.agent = agent || ''
        if(this.global === '') this.global = { crypto }
        this.ENCRYPTION_KEY_SUPPORT = 'EncryptionKeyContext';
        this.SECRET_KEYS_HEX = null;

        if (this.userKey === undefined || this.url === undefined) {
            throw new Error('Endpoint url and userKey are required in order to establish connection with the server.')
        }

    }

    set SECRET_KEY(data) {
        this.SECRET_KEYS_HEX = data;
    }

    async sendRequest(data) {
        const response = await this.fetch(this.url, {
            method: 'POST',
            headers: {
                'Content-Type': 'text/plain',
            },
            body: JSON.stringify(data),
            ...(this.agent !== '' && {
                agent: this.agent
            })
        })
        return response.json();
    }

    async getSymmetricKeyByTicket(TICKET_ID, userKey) {
        let [dbNoncePersonalHex, dbNonceHex, keys] = TICKET_ID.split("|");
        let [keyPersonal, keyCouple] = keys.split("-");
        let [key, keyVersion] = keyCouple.split("_");
        let dbNoncePersonal = this.fromHexString(dbNoncePersonalHex);
        let dbNonce = this.fromHexString(dbNonceHex)
        let symmetricKey
        if (this.SECRET_KEYS_HEX === null) {
            let userSecretKey = (await this.getKeyPairFromHashedUserKey(userKey)).secretKey;
            symmetricKey = this.decryptDataX25519(userSecretKey, dbNoncePersonal, this.fromHexString(keyPersonal));
        } else {
            let SecretKey = this.fromHexString(this.SECRET_KEYS_HEX[keyVersion])
            symmetricKey = this.decryptDataX25519(SecretKey, dbNonce, this.fromHexString(key));
        }

        return symmetricKey;
    }

    fromHexString(hexString) {
        return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    }

    toHex(buffer) {
        return Array.prototype.map.call(buffer, x => ('00' + x.toString(16)).slice(-2)).join('');
    }

    generateIv() {
        return this.global.crypto.getRandomValues(new Uint8Array(16));
    }

    async decryptDataAES256(key, iv, cipherData) {
        const cipherDataArray = this.fromHexString(cipherData);
        const cryptoKey = await this.global.crypto.subtle.importKey("raw", key, "AES-CBC", true, ['decrypt', 'encrypt']);
        const decryptedData = await this.global.crypto.subtle.decrypt(
            {
                name: "AES-CBC",
                iv
            },
            cryptoKey,
            cipherDataArray
        )
        const dec = new TextDecoder();
        const result = dec.decode(decryptedData);

        return result
    }

    async encryptDataAES256(iv, data, cryptoKey) {
        let enc = new TextEncoder();
        let encodedData = enc.encode(JSON.stringify(data));
        let cipherText = await this.global.crypto.subtle.encrypt(
            {
                name: 'AES-CBC',
                iv
            },
            cryptoKey,
            encodedData
        );

        let cipherTextString = [...new Uint8Array(cipherText)].map(x => x.toString(16).padStart(2, '0')).join('');
        return cipherTextString;
    }

    async getKeyPairFromHashedUserKey(UserKey) {
        try {
            let KeyPair
            if (UserKey) {
                const hashedUserKey = this.fromHexString(await this.sha256(this.ENCRYPTION_KEY_SUPPORT + UserKey));
                KeyPair = nacl.box.keyPair.fromSecretKey(hashedUserKey);
            } else {
                return false;
            }
            return KeyPair;
        } catch (err) {
            return false;
        }
    }

    async sha256(data) {
        const msgUint8 = new TextEncoder().encode(data);                              // encode as (utf-8) Uint8Array
        const hashBuffer = await this.global.crypto.subtle.digest('SHA-256', msgUint8);    // hash the data
        const hashArray = Array.from(new Uint8Array(hashBuffer));                     // convert buffer to byte array
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
        return hashHex;
    }

    decryptDataX25519(secretKey, nonce, box) {
        try {
            let openedBox = nacl.sealedbox.open(box, nonce, secretKey);
            return openedBox;
        } catch (err) {
            return null;
        }
    }

    async decryptTicket(ticket) {
        const ticketContent = ticket.CONTENT;
        const symmetricKey = await this.getSymmetricKeyByTicket(ticket.TICKET_ID, ticket.USER_KEY);
        let [dbIvTicketHex, content] = ticketContent.split('|');
        let dbIvTicket = this.fromHexString(dbIvTicketHex);
        let decryptedContent = JSON.parse(await this.decryptDataAES256(symmetricKey, dbIvTicket, content));

        return Object.assign(decryptedContent, { TICKET_ID: ticket.TICKET_ID, USER_KEY: ticket.USER_KEY });
    }

    async decryptStatus(ticketStatus, ticket) {

        const symmetricKey = await this.getSymmetricKeyByTicket(ticket.TICKET_ID, ticket.USER_KEY);
        const ticketStatusContent = ticketStatus.CONTENT;
        let [dbIvStatusHex, statusContent] = ticketStatusContent.split('|');
        let dbIvStatus = this.fromHexString(dbIvStatusHex);

        let decryptedContent = JSON.parse(await this.decryptDataAES256(symmetricKey, dbIvStatus, statusContent));

        return decryptedContent;
    }

    async decryptMessages(ticketMessages, ticket) {
        const symmetricKey = await this.getSymmetricKeyByTicket(ticket.TICKET_ID, ticket.USER_KEY);
        let decryptedContent = [];

        for (let index = 0; index < ticketMessages.length; index++) {
            const el = ticketMessages[index];
            if (el !== null) {
                const ticketMessageContent = el.CONTENT;
                let [dbIvMessageHex, messageContent] = ticketMessageContent.split('|');
                let dbIvMessage = this.fromHexString(dbIvMessageHex);
                const result = await this.decryptDataAES256(symmetricKey, dbIvMessage, messageContent);

                decryptedContent.push(Object.assign(JSON.parse(result), { "MESSAGE_ID": el.RANDOM_ID }));
            }
        }

        return decryptedContent
    }

    async decryptAttachment(attachment, ticketID) {
        const symmetricKey = await this.getSymmetricKeyByTicket(ticketID, this.userKey);
        let [dbIvAttachmentHex, attachmentContent] = attachment.split('|');
        let dbIvAttachment = this.fromHexString(dbIvAttachmentHex);
        const result = await this.decryptDataAES256(symmetricKey, dbIvAttachment, attachmentContent);
        return JSON.parse(result);
    }

    async decryptMessageStatuses(statusesList, ticketID) {
        const symmetricKey = await this.getSymmetricKeyByTicket(ticketID, this.userKey);
        let decryptedStatuses = [];

        for (let i = 0; i < statusesList.length; i++) {
            const element = statusesList[i];

            let [dbIvStatusHex, statusContent] = element.CONTENT.split("|");
            let dbIvStatus = this.fromHexString(dbIvStatusHex)
            const result = await this.decryptDataAES256(symmetricKey, dbIvStatus, statusContent);
            decryptedStatuses.push(Object.assign(JSON.parse(result), { "MESSAGE_ID": element.MESSAGE_ID }))
        }
        return decryptedStatuses;
    }

    generateNonce() {
        const nonce = this.global.crypto.getRandomValues(new Uint8Array(24));
        return nonce
    }

    encryptDataX25519(publicKey, nonce, data) {
        try {
            let sealedBox = nacl.sealedbox(data, nonce, publicKey);
            return sealedBox;
        } catch (err) {
            return err
        }
    }

    getKeyVersion() {
        return '1.1.0';
    }

    getPublicKeyHex(KeyVersion) {
        const PUBLIC_KEYS_HEX = {
            "1.0.0": "437260363885d812f028b762e7d5fb7154c707a16760d0865ca717879917c057",
            "1.1.0": "c7f76030e39f374d2a4ec894b9abc07e4c9e2880cb522e1e1230754dd8aba700"
        }
        if (KeyVersion) {
            return PUBLIC_KEYS_HEX[KeyVersion];
        } else {
            return PUBLIC_KEYS_HEX['1.0.0'];
        }
    }

    generateSymmetricKey() {
        try {
            return this.global.crypto.subtle.generateKey(
                {
                    name: "AES-CBC",
                    length: 256
                },
                true,
                ["encrypt", "decrypt"]
            )
        } catch (err) {
            return false;
        }
    }

    async getTicketID(userKey, symmetricCryptoKey, PublicKeyHex) {
        try {
            const symmetricKey = new Uint8Array(await this.global.crypto.subtle.exportKey('raw', symmetricCryptoKey));
            const userNonce = this.generateNonce();
            const Nonce = this.generateNonce();
            const UserKeyPair = await this.getKeyPairFromHashedUserKey(userKey);
            const PublicKey = this.fromHexString(PublicKeyHex);
            const KeyVerion = this.getKeyVersion();
            const symmetricKeyEncryptedWithUserKey = this.encryptDataX25519(UserKeyPair.publicKey, userNonce, symmetricKey);
            const symmetricKeyEncryptedWithUserKeyHex = this.toHex(symmetricKeyEncryptedWithUserKey);;
            const symmetricKeyEncryptedWithKey = this.encryptDataX25519(PublicKey, Nonce, symmetricKey);
            const symmetricKeyEncryptedWithKeyHex = this.toHex(symmetricKeyEncryptedWithKey) + '_' + KeyVerion;
            return this.toHex(userNonce) + '|' + this.toHex(Nonce) + '|' + symmetricKeyEncryptedWithUserKeyHex + '-' + symmetricKeyEncryptedWithKeyHex;
        } catch (err) {
            return false;
        }
    }

    async composeTicketContent(data, symmetricCryptoKey) {
        /* Required data format
            {
                "isGuest": boolean,
                "subject": id [number],
                "lang": null,
                "type": string,
                "from_support_id": null
            }
        */
        let isGuest = !!data.isGuest;
        let subject = data.subject ? data.subject : '1';
        let lang = data.lang ? data.lange : null;
        let type = data.type ? data.type : 'support';
        let from_support_id = null;
        let email = data.email ? data.email : null;

        let pureContent = {
            creation_date: Date.now(),
            subject,
            lang,
            type,
            from_support_id,
            isGuest,
            email
        }

        const iv = this.generateIv();
        const ivHex = this.toHex(iv);
        const encryptedContent = await this.encryptDataAES256(iv, pureContent, symmetricCryptoKey)

        return ivHex + '|' + encryptedContent
    }

    async composeTicketStatus(data, symmetricCryptoKey) {
        /* Required data format
            {
                "status": string,
            }
        */
        const ticketStatusOptions = ['Pending', 'Answered', 'Closed', 'Resolved'] // possible ticket statuses ordered according to the typical ticket lifecycle (only important to have the initial status at 0-index)
        let status = data.ticketStatus ? data.ticketStatus : 'Pending';

        if (!ticketStatusOptions.includes(status)) {
            throw new Error("Invalid ticket status.")
        }
        let pureContent = {
            status_date: Date.now(),
            status
        }
        const iv = this.generateIv();
        const ivHex = this.toHex(iv);
        const encryptedContent = await this.encryptDataAES256(iv, pureContent, symmetricCryptoKey)

        return ivHex + '|' + encryptedContent
    }

    async composeTicketMessage(data, symmetricCryptoKey) {
        /* Required data format
            {
                creation_date: 
                from_support_id: If it comes from the support there is an ID, else it's null (or maybe -1?)
                message: 
                message_type: // not sure what's in it for now 
                message_id: // 64 char Hex - random MessageID 
                attachments: 
            }
        */
        let message = data.message ? data.message : "";
        let from_support_id = data.supportID ? data.supportID : null;
        let message_type = data.message_type ? data.message_type : null;
        let attachments = data.attachments ? data.attachments : [];

        let pureContent = {
            creation_date: Date.now(),
            from_support_id,
            message,
            message_type,
            attachments: attachments.map(el => {
                return {
                    "mime_type": el.mime_type,
                    "name": el.name,
                    "ATTACHMENT_ID": el.ATTACHMENT_ID
                }
            })
        }
        const iv = this.generateIv();
        const ivHex = this.toHex(iv);
        const encryptedContent = await this.encryptDataAES256(iv, pureContent, symmetricCryptoKey)

        return ivHex + '|' + encryptedContent
    }

    async composeMessageStatus(data, symmetricCryptoKey) {
        /* Required data format
            {
                messageStatus 
            }
        */
        let status = data.messageStatus ? data.messageStatus : 'unread';

        let pureContent = {
            status_date: Date.now(),
            status
        }
        const iv = this.generateIv();
        const ivHex = this.toHex(iv);
        const encryptedContent = await this.encryptDataAES256(iv, pureContent, symmetricCryptoKey)

        return ivHex + '|' + encryptedContent
    }

    async composeAttachments(data, symmetricCryptoKey) {
        /* Required data format
            {
                attachments: [object]
            }
        */
        let attachments = data.attachments ? data.attachments : [];
        let result = []
        for (let i = 0; i < attachments.length; i++) {
            const element = attachments[i];
            const iv = this.generateIv();
            const ivHex = this.toHex(iv);
            const encryptedContent = await this.encryptDataAES256(iv, { "base64": element.base64 }, symmetricCryptoKey)
            result.push(
                {
                    CONTENT: ivHex + '|' + encryptedContent,
                    hash: await this.sha256(element.ATTACHMENT_ID)
                }
            )
        }
        return result
    }

    async composeRequest(type, requestData) {
        // const symmetricCryptoKey = await this.generateSymmetricKey();
        // const KeyVerion = this.getKeyVersion();
        // const PublicKeyHex = this.getPublicKeyHex(KeyVerion);
        // const REQUEST_ID = await this.getRequestID(this.userKey, symmetricCryptoKey, PublicKeyHex);
        const pureData = {
            "type": type,
            "data": requestData
        }
        // let iv = this.generateIv();
        // const encryptedData = await this.encryptDataAES256(iv, pureData, symmetricCryptoKey);
        // const result = await this.sendRequest(REQUEST_ID + "||" + this.toHex(iv) + "||" + encryptedData)
        const result = await this.sendRequest(pureData)
        if (result.error == true) {
            throw new Error(result.data.msg)
        } else if (result.error == false) {
            return result
        } else {
            throw new Error("General response error.")
        }
    }

    async generateTicketKeys(userKey) {
        const symmetricCryptoKey = await this.generateSymmetricKey();
        const KeyVerion = this.getKeyVersion();
        const PublicKeyHex = this.getPublicKeyHex(KeyVerion);
        const TICKET_ID = await this.getTicketID(userKey, symmetricCryptoKey, PublicKeyHex);

        return {
            symmetricCryptoKey,
            TICKET_ID
        }
    }

    async decryptTicketList(ticketList) {
        let result = [];
        if (ticketList && Array.isArray(ticketList)) {
            for (let index = 0; index < ticketList.length; index++) {
                try{
                    const el = ticketList[index];
                    const ticket = el.ticket;
                    const status = el.status;
                    const messages = el.messages;
                    let decryptedMessages = await this.decryptMessages(messages, ticket);
                    const decryptedStatuses = await this.decryptMessageStatuses(el.messageStatuses, ticket.TICKET_ID)
                    decryptedMessages = decryptedMessages.map(el => {
                        const messageID = el.MESSAGE_ID;
                        const matchingStatus = decryptedStatuses.find(el => el.MESSAGE_ID === messageID);
                        return Object.assign(el, { "status_date": matchingStatus.status_date, "status": matchingStatus.status })
                    })
                    const resultObj = {
                        "ticket": await this.decryptTicket(ticket),
                        "status": await this.decryptStatus(status, ticket),
                        "messages": decryptedMessages,
                    }
                    result.push(resultObj);
                }catch(err){
                    console.error('Decryption error:', err.message)
                }
            }
            return result;
        } else {
            throw new Error('Passed data must be encrypted ticket list')
        }
    }

    async readAllTickets(data) {
        /* Valid data format:
            {
                "userKey": string REQUIRED
                "hashData": string OPTIONAL,
                "page": number OPTIONAL,
                "pageSize": number OPTIONAL
            }
        */
        if (!data.hasOwnProperty('userKey')) {
            throw new Error('Passed data must include userKey property.')
        }
        const response = await this.composeRequest('READ_ALL_TICKET_LIST', data)
        if (response.error === false && response.data) {
            if (response.data[0] !== 'No ticket changes.') {
                return {
                    "hashData": await this.sha256(JSON.stringify(response.data)),
                    "data": await this.decryptTicketList(response.data)
                };
            } else {
                return 'No ticket changes.';
            }
        } else {
            return response;
        }
    }

    async createTicket(data) {
        /* Valid data format:
            {
                "isGuest": false,
                "subject": "1",
                "lang": null, 
                "type": "support",
                "message": "Test message send through automated tests.",
                "message_type": null,
                "email": null,
                "attachments": [{"mime_type":"image/jpg","name":"file1","base64":"mockBase64String","ATTACHMENT_ID":"123"},
                {"mime_type":"image/jpg","name":"file2","base64":"mockBase64String2","ATTACHMENT_ID":"456"}]
            }
        */
        let KeyPair
        if(!data.symmetricCryptoKey || !data.TICKET_ID){
            KeyPair = await this.generateTicketKeys(this.userKey)
        }
        const symmetricCryptoKey = KeyPair ? KeyPair.symmetricCryptoKey : data.symmetricCryptoKey;
        const TICKET_ID = KeyPair ?  KeyPair.TICKET_ID : data.TICKET_ID;

        const requestData = {
            "userKey": this.userKey,
            "ticketID": TICKET_ID,
            "ticket": await this.composeTicketContent(data, symmetricCryptoKey),
            "ticketStatus": await this.composeTicketStatus(data, symmetricCryptoKey),
            "message": await this.composeTicketMessage(data, symmetricCryptoKey),
            "messageStatus": await this.composeMessageStatus(data, symmetricCryptoKey),
            "attachments": await this.composeAttachments(data, symmetricCryptoKey)
        }
        return this.composeRequest('CREATE_CONVERSATION', requestData);
    }

    deleteTicket(data) {
        /* Valid data format:
            {
                "ticketID": string REQUIRED
            }
        */
        if (!data.hasOwnProperty('ticketID')) {
            throw new Error('Passed data must include ticketID property.')
        }
        return this.composeRequest('DELETE_CONVERSATION', { ticketID: data.ticketID, userKey: this.userKey });
    }

    deleteMessage(data) {
        /* Valid data format:
            {
                "ticketID": string, REQUIRED
                "messageID": string REQUIRED
            }
        */
        if (!data.hasOwnProperty('ticketID')) {
            throw new Error('Passed data must include ticketID property.')
        }
        if (!data.hasOwnProperty('messageID')) {
            throw new Error('Passed data must include messageID property.')
        }
        return this.composeRequest('DELETE_MESSAGE', {
            "userKey": this.userKey,
            "ticketID": data.ticketID,
            "messageID": data.messageID
        });
    }

    async changeTicketStatus(data) {
        /* Valid data format:
            {
                "ticketStatus": string REQUIRED
                "ticketID": string REQUIRED
            }
        */
        if (!data.hasOwnProperty('ticketStatus')) {
            throw new Error('Passed data must include new status.')
        }
        const symmetricKey = await this.getSymmetricKeyByTicket(data.ticketID, this.userKey)
        const symmetricCryptoKey = await this.global.crypto.subtle.importKey('raw', symmetricKey, "AES-CBC", true, ['encrypt', 'decrypt'])

        let requestData = {
            "userKey": this.userKey,
            "ticketID": data.ticketID,
            "content": await this.composeTicketStatus(data, symmetricCryptoKey)
        }
        return this.composeRequest('CHANGE_STATUS', requestData);
    }

    async createMessage(data) {
        /* Valid data format:
            {
                "ticketID": string
                "message": string,
                "attachments": [object],
                "supportID": string OPTIONAL
            }

            attachmentObj = {
                mime_type,
                name,
                base64,
                ATTACHMENT_ID
            }

            ** Message must at least include a message or an attachment.
        */

        if ((data.message && data.message.length !== 0) || (data.attachments && data.attachments.lenght !== 0)) {
        } else {
            throw new Error('Passed data must include a message or an attachments array.')
        }
        if (!data.hasOwnProperty('ticketID')) {
            throw new Error('Passed data must include ticketID property.')
        }

        const symmetricKey = await this.getSymmetricKeyByTicket(data.ticketID, this.userKey)
        const symmetricCryptoKey = await this.global.crypto.subtle.importKey('raw', symmetricKey, "AES-CBC", true, ['encrypt', 'decrypt'])
        let requestData = {
            "userKey": this.userKey,
            "ticketID": data.ticketID,
            "message": await this.composeTicketMessage(data, symmetricCryptoKey),
            "messageStatus": await this.composeMessageStatus(data, symmetricCryptoKey),
            "attachments": await this.composeAttachments(data, symmetricCryptoKey)
        }

        return this.composeRequest('SEND_MESSAGE', requestData);
    }

    async readSingleTicket(data) {
        /* Valid data format:
            {
                "ticketID": string REQUIRED
            }
        */
        if (!data.hasOwnProperty('ticketID')) {
            throw new Error('Passed data must include ticketID property.')
        }
        const response = await this.composeRequest('READ_SINGLE_TICKET', {
            "userKey": this.userKey,
            "ticketID": data.ticketID
        })
        if (response.error === false && response.data) {
            return (await this.decryptTicketList([response.data]))[0];
        } else {
            return response;
        }
    }

    async getAttachment(data) {
        /* Valid data format:
            {
                "ticketID": string REQUIRED
                "attachmentID": string REQUIRED
            }
        */
        if (!data.hasOwnProperty('ticketID')) {
            throw new Error('Passed data must include ticketID property.')
        }
        if (!data.hasOwnProperty('attachmentID')) {
            throw new Error('Passed data must include attachmentID property.')
        }
        const response = await this.composeRequest('GET_ATTACHMENT', {
            "hashedAttachmentID": await this.sha256(data.attachmentID)
        })
        if (response.error === false && response.data) {
            return (await this.decryptAttachment(response.data.CONTENT, data.ticketID));
        } else {
            return response;
        }
    }

    async changeMessageStatus(data) {
        /* Valid data format:
            {
                "messageStatus": string REQUIRED,
                "messageID": string REQUIRED,
                "ticketID": string REQUIRED
            }
        */
        if (!data.hasOwnProperty('messageStatus')) {
            throw new Error('Passed data must include new status.')
        }
        if (!data.hasOwnProperty('messageID')) {
            throw new Error('Passed data must include messageID.')
        }
        if (!data.hasOwnProperty('ticketID')) {
            throw new Error('Passed data must include ticketID.')
        }
        const symmetricKey = await this.getSymmetricKeyByTicket(data.ticketID, this.userKey)
        const symmetricCryptoKey = await this.global.crypto.subtle.importKey('raw', symmetricKey, "AES-CBC", true, ['encrypt', 'decrypt'])

        let requestData = {
            "ticketID": data.ticketID,
            "messageID": data.messageID,
            "messageStatus": await this.composeMessageStatus(data, symmetricCryptoKey),
            "userKey": this.userKey
        }
        return this.composeRequest('CHANGE_MESSAGE_STATUS', requestData);
    }

    async getSubjectMaps() {

        return this.composeRequest('GET_SUBJECT_MAPS');
    }

    async getTicketStatusHistory(data) {

        let response = await this.composeRequest('GET_TICKET_STATUS_HISTORY', {
            "ticketID": data.ticketID,
            "userKey": this.userKey
        })
        if(response.error == false) {
            let decryptedStatuses = await Promise.all (response.data.map(status => this.decryptStatus(status,{
                TICKET_ID: data.ticketID,
                USER_KEY: this.userKey
                })
            ))
            return decryptedStatuses
        }else {
            throw new Error(response.msg)
        }
    }

}

export default SupportClient