import client from '../index.js'
let assert = chai.assert

let SupportClient = null
let keys = null

describe('Client encrypts and decrypts data successfully.', function () {
    const userKey = "9930c31575197861405d2346de765baab1b77900adb192d0243fe4db8e0b314a";
    // Valid ticket data format:
    const newTicketData = {
        "isGuest": false,
        "subject": "1",
        "lang": null, 
        "type": "support",
        "message": "Test message send through automated tests.",
        "message_type": null,
        "email": null,
        "attachments": [
            { "mime_type": "image/jpg", "name": "file1", "base64": "mockBase64String", "ATTACHMENT_ID": "123" },
            { "mime_type": "image/jpg", "name": "file2", "base64": "mockBase64String2", "ATTACHMENT_ID": "456" }
        ]
    }
    
    describe('SupportClient composes request data.', function () {
        it('Creates SupportClient instance.', function () {
            SupportClient = new client('endpoint', userKey)
            assert.ok(SupportClient, 'Instance of SupportClient not created.');
            assert.equal(SupportClient.userKey, userKey, 'User key not saved withing the instance of SupportClient.')
        });
        it('Generates ticket ID and symmetric crypto key.', async function () {
            keys = await SupportClient.generateTicketKeys(userKey)
            assert.property(keys, 'symmetricCryptoKey', 'Generated keys object does not have "symmetricCryptoKey" property.');
            assert.property(keys, 'ticketID', 'Generated keys object does not have "ticketID" property.');
            assert.match(keys.ticketID, /^([\da-f]{48}\|){2}[\da-f]{160}-[\da-f]{160}_[\d\.]+$/, 'Generated ticket ID does not match the expected string structure.')
        });
        it('Composes an encrypted ticket data.', async function () {
            let encryptedTicketString = await SupportClient.composeTicketContent(newTicketData, keys.symmetricCryptoKey)
            assert.equal(typeof encryptedTicketString, 'string', 'Composed encrypted ticket is not a string.');
            assert.match(encryptedTicketString, /^[\da-f]{32}\|[\da-f]+$/, 'Composed encrypted string does not match the expected string structure.');
        });
        it('Composes an encrypted ticket status.', async function () {
            let encryptedTicketStatusString = await SupportClient.composeTicketStatus(newTicketData, keys.symmetricCryptoKey)
            assert.equal(typeof encryptedTicketStatusString, 'string', 'Composed encrypted ticket status is not a string.');
            assert.match(encryptedTicketStatusString, /^[\da-f]{32}\|[\da-f]+$/, 'Composed encrypted string does not match the expected string structure.');
        });
        it('Composes an encrypted message.', async function () {
            let encryptedTicketMessageString = await SupportClient.composeTicketMessage(newTicketData, keys.symmetricCryptoKey)
            assert.equal(typeof encryptedTicketMessageString, 'string', 'Composed encrypted ticket message is not a string.');
            assert.match(encryptedTicketMessageString, /^[\da-f]{32}\|[\da-f]+$/, 'Composed encrypted string does not match the expected string structure.');
        });
        it('Composes an encrypted message status.', async function () {
            let encryptedTicketMessageStatusString = await SupportClient.composeMessageStatus(newTicketData, keys.symmetricCryptoKey)
            assert.equal(typeof encryptedTicketMessageStatusString, 'string', 'Composed encrypted message status is not a string.');
            assert.match(encryptedTicketMessageStatusString, /^[\da-f]{32}\|[\da-f]+$/, 'Composed encrypted string does not match the expected string structure.');
        });
        it('Composes an encrypted ticket attachments.', async function () {
            let encryptedTicketAttachments = await SupportClient.composeAttachments(newTicketData, keys.symmetricCryptoKey)
            assert.ok(Array.isArray(encryptedTicketAttachments), 'Composed encrypted attachments is not an array.');
            for (const attachment of encryptedTicketAttachments) {
                assert.match(attachment['content'], /^[\da-f]{32}\|[\da-f]+$/, 'Composed encrypted string does not match the expected string structure.');
                assert.match(attachment['hash'], /^[\da-f]{64}$/, 'Attachment hashed ID does not match the expected string structure.');
            }
        });
    });
    describe('SupportClient decrypts the composed data.', function () {
        it('Decrypts encrypted ticket data.', async function () {
            let encryptedTicketString = await SupportClient.composeTicketContent(newTicketData, keys.symmetricCryptoKey)
            let decryptedTicketObject = await SupportClient.decryptTicket({
                'content': encryptedTicketString,
                'ticketID': keys.ticketID,
                'userKey': userKey
            })
            assert.isObject(decryptedTicketObject, 'Decryption result is not an object.')
            assert.equal(decryptedTicketObject.type, newTicketData.type, 'Decrypted ticket "type" does not match the ticket "type" of the initial data.')
            assert.equal(decryptedTicketObject.ticketID, keys.ticketID, 'Decrypted ticket "ticketID" does not match the ticket "ticketID" of the initial data.')
            assert.equal(decryptedTicketObject.userKey, userKey, 'Decrypted ticket "userKey" does not match the ticket "userKey" of the initial data.')
        });
        it('Decrypts encrypted ticket status.', async function () {
            let encryptedTicketStatusString = await SupportClient.composeTicketStatus(newTicketData, keys.symmetricCryptoKey)
            let decryptedTicketStatusObject = await SupportClient.decryptStatus(
                {
                    'content': encryptedTicketStatusString
                },
                {
                    'ticketID': keys.ticketID,
                    'userKey': userKey
                }
            )
            assert.isObject(decryptedTicketStatusObject, 'Decryption result is not an object.')
            assert.equal(decryptedTicketStatusObject.status, 'Pending', 'Decrypted ticket status is not "Pending".')
        });
        it('Decrypts encrypted ticket messages.', async function () {
            let encryptedTicketMessageString = await SupportClient.composeTicketMessage(newTicketData, keys.symmetricCryptoKey)
            
            let decryptedTicketMessagesArray = await SupportClient.decryptMessages(
                [
                    { "content": encryptedTicketMessageString }
                ],
                {
                    'ticketID': keys.ticketID,
                    'userKey': userKey
                }
            )
            assert.isArray(decryptedTicketMessagesArray, 'Decryption result is not an array.')
            assert.equal(decryptedTicketMessagesArray[0].message, newTicketData.message, 'Decrypted ticket message does not match the ticket message of the initial data.')

        });
        it('Decrypts encrypted message status.', async function () {
            let encryptedMessageStatusString = await SupportClient.composeMessageStatus(newTicketData, keys.symmetricCryptoKey)
            
            let decryptedMessageStatusArray = await SupportClient.decryptMessageStatuses(
                [
                    { "content": encryptedMessageStatusString }
                ],
                keys.ticketID,
            )
            assert.isArray(decryptedMessageStatusArray, 'Decryption result is not an array.')
            assert.equal(decryptedMessageStatusArray[0].status, 'unread', 'Decrypted message status is not "unread".')
        });
        it('Decrypts encrypted ticket attachment.', async function () {
            let encryptedTicketAttachments = await SupportClient.composeAttachments(newTicketData, keys.symmetricCryptoKey)
            
            let decryptedTicketAttachment = await SupportClient.decryptAttachment(
                encryptedTicketAttachments[0]['content'],
                keys.ticketID,
            )
            assert.isObject(decryptedTicketAttachment, 'Decryption result is not an object.')
            assert.equal(decryptedTicketAttachment.base64, newTicketData.attachments[0].base64, 'Decrypted attachment base64 representation does not match the initial value.')
        });
    });
});

mocha.run()