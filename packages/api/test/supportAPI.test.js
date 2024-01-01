const assert = require('assert');
const { sha256 } = require('../src/helpers/dataEncryption');
const { createConversation, deleteConversation, readAllTicketList, addTicketMessage, deleteTicketMessage, changeTicketStatus, readSingleTicket, changeMessageStatus, getAttachment, getSubjectMaps, getTicketStatusHistory } = require('../src/scripts/handle-requests');

describe('API Handles received data accordingly.', function () {
    const userKey = "992a8ec5972664c2ee38aa66e6fe802d1b23fcccf91c164e01b1f1ea1f9abddb";
    // Valid ticket request data
    const requestData = {
        "userKey": userKey,
        "ticketID": "be5c7fd1d93eca2a8e42b8a62519b6056c001e39a188b699|f24e2b1e60dc20cc4072689c682a5f52f4b6c54882f54b9b|48f5bc02799ac25d4b21248b4e4df109431f26a21eb7c93b5eb221e284760649f98b3d0a760657b9440e4c2b5ec3da6ebf2187aff8d35d7223f361dfdb034b69d40fc88bc20887a38783d8abea612076-cc11cf0df52ec6e1dfdde971ba74df7eeb3c38b5d930e15aca6ce35019e9544d3c5c76ce67af8348809c47b374313b960c17052c4283c2d2d2b15bd5ad4f245913942df64c34f44e0338eaed8a1d6ddc_1.1.0",
        "ticket": "caf96ab39d9be0651b989443e409cafe|901a4cbcb1caed816f746cf7b64a0387c6c5269229bd1a22a111d440a5da3c95fefdacb9d0786b6c59cac378c6bca954d2483f260ac5d212193a06c8b6eb6ecf09e6bff025279f5bf44c67551509344ba587465c0b77a7eb088713fbe9b7d949c47e2bc75c488ff4fedfff98c41dda74fe211bc41eeb286789d60e699c3b257a",
        "ticketStatus": "ba2b35c1629fe5c2ecae583ac947ab16|d8f69be99ac4daf6721bcf313e8ae623a15b0b5f586789a4e0eda5c534f30dd0e0b196ef16c839eb60d187475a05eca04b1de24bf85efd830bbced97ff9a15e1",
        "message": "ecc989f67ea0e9e235573e66bfd70384|69e7271dea24d14a3c511debb478b69300be34f0308c3fe1f671231bcad1971236ae1d73b35ee19a4424716493eced2f700b9d2ab8b24ce2c917e478c1c436ccac8ee8cce06b8ec4603bec3e46b30e51b90fbd22af973d1ad7f49d2b5f663066f847b95b48c4d03f19509e1df993329c2a88ef60f6b4f35960c9233266fd4992d7097be0e7bd05c8713f9d3dee74214f0e3e07dbad1a38d47d945df4af18d6b3ddddecd7ee554a95bd8b85181660e989d145ed15184e4d5281a9a64525ce9e7681462d995130ad9d9cfd19110d0c179d253beff74827730be28a1fd2cf189a692e7fbb4f7a4c382429280a6dba453f4928d74e82a4594c095082fcb4a1a437a3c4b75efaf563f2c866d25813bab67fa6",
        "messageStatus": "be39807d8129762f8b4b46cc83cceaf5|437a72faa78cf4ebdb91874d7432bc8dbb059b98b5473845a5410f1666c7066d7fb9c262890b021b92d2941590c9dc06",
        "attachments": [
          {
            "content": "8376f1f24292577172e1d8819070d19d|6b8083309ea47c5e0a19dc0c8fa0abd860a38994947f2e99c068b8c1985330e4",
            "hash": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
          },
          {
            "content": "83470c53fc1ff3b8ff0d167798b1dd8a|633190676d89d4379c05dbac199936031f1debdbd3cc6c3a31f0ae34825e8ace",
            "hash": "b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0"
          }
        ]
    }
    let messageID = null
    let hashedLoadedData = null
    describe('Creates ticket elements and saves them to the DB', function () {
        it('Creates a ticket if all the data is valid.', async function () {
            let resultData = createConversation(requestData, requestData['ticketID'], userKey);
            assert.equal(resultData.msg, 'Success', 'The request data is invalid or the DB commands have thrown an error.');
        });
        it('Returns an error string if the message is too long.', async function () {
            let modifiedRequestData = { ...requestData };
            modifiedRequestData['message'] = requestData['message'].repeat(25);
            let resultData = createConversation(modifiedRequestData, requestData['ticketID'], userKey);
            assert.equal(resultData, 'Message is too long.', `Message length limit has not been exceeded or a different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Adds new message to an existing ticket.', async function () {
            let resultData = addTicketMessage(requestData.ticketID, userKey, requestData);
            assert.equal(resultData, 'Success', 'The request data is invalid or the DB commands have thrown an error.');
        });
        it('Returns an error string when adding a message if the ticket does not exsist.', async function () {
            let resultData = addTicketMessage(requestData.ticketID + 'invalidating_id', userKey, requestData);
            assert.equal(resultData, 'Ticket does not exist.', `Ticket object validation has not been hit or different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Returns an error string when adding a message if the user is not an author.', async function () {
            let resultData = addTicketMessage(requestData.ticketID, userKey + 'invalidating_key', requestData);
            assert.equal(resultData, 'User not authorized.', `User key matches a support member ID or a different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Changes the ticket status.', async function () {
            let resultData = changeTicketStatus(requestData.ticketID, requestData['ticketStatus'], userKey);
            assert.equal(resultData, 'Success', 'The request data is invalid or a different error has been thrown.');
        });
        it('Returns an error string when changing ticket status if the ticket does not exsist.', async function () {
            let resultData = changeTicketStatus(requestData.ticketID + 'invalidating_id', requestData['ticketStatus'], userKey);
            assert.equal(resultData, 'Ticket does not exist.', `Ticket object validation has not been hit or different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Returns an error string when changing ticket status if the user is not an author.', async function () {
            let resultData = changeTicketStatus(requestData.ticketID, requestData['ticketStatus'], userKey + 'invalidating_key');
            assert.equal(resultData, 'User is not authorized.', `User key matches a support member ID or a different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Changes the message status.', async function () {
            let resultData = changeMessageStatus(requestData.messageStatus, messageID, requestData.ticketID, userKey);
            assert.equal(resultData, 'Success', 'The request data is invalid or a different error has been thrown.');
        });
        it('Returns an error string when changing message status if the ticket does not exsist.', async function () {
            let resultData = changeMessageStatus(requestData.messageStatus, messageID, requestData.ticketID + 'invalidating_id', userKey);
            assert.equal(resultData, 'Ticket does not exist.', `Ticket object validation has not been hit or different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Returns an error string when changing message status if the user is not an author.', async function () {
            let resultData = changeMessageStatus(requestData.messageStatus, messageID, requestData.ticketID, userKey + 'invalidating_key');
            assert.equal(resultData, 'User not authorized.', `User key matches a support member ID or a different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
    });
    describe('Reads data saved in the DB.', function () {
        it('Reads all tickets by a selected user key.', async function () {
            let resultData = readAllTicketList(userKey);
            messageID = resultData[0]['messages'][0]['RANDOM_ID'];
            hashedLoadedData = sha256(JSON.stringify(resultData));
            assert.ok(Array.isArray(resultData), `The returned result is not an Array. Check function result for further information. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
            assert.equal(resultData.length, 1, 'Length of the returned array does not match the expected length.');
        });
        it('Sends a string confirmation if there have been no changes in the loaded tickets.', async function () {
            let resultData = readAllTicketList(userKey,hashedLoadedData);
            assert.ok(Array.isArray(resultData), `The returned result is not an Array. Check function result for further information. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
            assert.equal(resultData[0], 'No ticket changes.', 'Ticket data has been modified or a different error has been thrown.');
        });
        it('Reads a single ticket by Ticket ID.', async function () {
            let resultData = readSingleTicket(requestData.ticketID, userKey);
            assert.equal(typeof resultData, 'object', `The returned result is not an Object. Check function result for further information. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
            assert.ok(resultData['ticket'], 'The returned result object structure does not match the expected one. There is no "ticket" key in the returned object.');
        });
        it('Returns an error string if a ticket does not exsist when reading single ticket.', async function () {
            let resultData = readSingleTicket(requestData.ticketID + 'invalidating_id', userKey);
            assert.equal(resultData, 'Ticket does not exist.', `Ticket object validation has not been hit or different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Returns an error string if the user is not author when reading single ticket.', async function () {
            let resultData = readSingleTicket(requestData.ticketID, userKey + 'invalidating_key');
            assert.equal(resultData, 'User not authorized to fetch current ticket.', `User key matches a support member ID or a different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Reads an attachment based on Attachment ID', async function () {
            let resultData = getAttachment(requestData.attachments[0].hash);
            assert.equal(typeof resultData, 'object', `The returned result is not an Object. Check function result for further information. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
            assert.ok(resultData['content'], 'The returned result object structure does not match the expected one. There is no "content" key in the returned object.');
        });
        it('Returns undefined if the Attachment ID is invalid.', async function () {
            let resultData = getAttachment(requestData.attachments[0].hash + 'invalidating_id');
            assert.equal(resultData, undefined, `The returned result is not "undefined". ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Reads subject maps.', async function () {
            let resultData = getSubjectMaps();
            assert.equal(typeof resultData, 'object', `The returned result is not an Object. Check function result for further information. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
            assert.ok(resultData['maps'], 'The returned result object structure does not match the expected one. There is no "maps" key in the returned object.');
        });
        it('Reads ticket status history.', async function () {
            let resultData = getTicketStatusHistory(requestData.ticketID, userKey);
            assert.ok(Array.isArray(resultData), `The returned result is not an Array. Check function result for further information. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
            assert.equal(resultData.length, 2, 'Length of the returned array does not match the expected length.');
        });
        it('Returns an error string if a ticket does not exsist when reading ticket status history.', async function () {
            let resultData = getTicketStatusHistory(requestData.ticketID + 'invalidating_id', userKey);
            assert.equal(resultData, 'Ticket does not exist.', `Ticket object validation has not been hit or different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Returns an error string if the user is not author when reading ticket status history.', async function () {
            let resultData = getTicketStatusHistory(requestData.ticketID, userKey + 'invalidating_key');
            assert.equal(resultData, 'User not authorized to fetch current ticket.', `User key matches a support member ID or a different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
    });
    describe('Deletes data saved in the DB.', function () {
        it('Returns an error string if the ticket ID is invalid when deleting a message', async function () {
            let resultData = deleteTicketMessage(messageID, requestData.ticketID + 'invalidating_id', userKey);
            assert.equal(resultData, 'Ticket does not exist.', `Ticket object validation has not been hit or different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Returns an error string if the user is not an author when deleting a message', async function () {
            let resultData = deleteTicketMessage(messageID, requestData.ticketID, userKey + 'invalidating_key');
            assert.equal(resultData, 'User is not authorized.', `User key matches a support member ID or a different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Deletes a message by a message ID', async function () {
            assert.equal(readAllTicketList(userKey)[0]['messages'].length, 2, 'Length of the ticket messages array does not match the expected length.');
            let resultData = deleteTicketMessage(messageID, requestData.ticketID, userKey);
            assert.equal(resultData, 'Success', `The request data is invalid or a different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
            assert.equal(readAllTicketList(userKey)[0]['messages'].length, 1, 'Length of the ticket messages array does not match the expected length.');
        });
        it('Returns an error string if Ticket ID is invalid when trying to delete a ticket.', async function () {
            let resultData = deleteConversation(requestData.ticketID + 'invalidating_id', userKey);
            assert.equal(resultData, 'Ticket does not exist.', `Ticket object validation has not been hit or different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Returns an error string if user is not author when trying to delete a ticket.', async function () {
            let resultData = deleteConversation(requestData.ticketID, userKey + 'invalidating_key');
            assert.equal(resultData, 'User is not authorized.', `User key matches a support member ID or a different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
        });
        it('Deletes exsisting tickets by Ticket ID.', async function () {
            let resultData = deleteConversation(requestData.ticketID, userKey);
            assert.equal(resultData, 'Success', `The request data is invalid or a different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
            assert.equal(readAllTicketList(userKey).length, 0, 'Length of the returned array does not match the expected length.');
        });
        it('Deletes the ticket if the last message has been deleted.', async function () {
            createConversation(requestData, requestData['ticketID'], userKey);
            messageID = readAllTicketList(userKey)[0]['messages'][0]['RANDOM_ID'];
            assert.equal(readAllTicketList(userKey).length, 1, 'Length of the returned array does not match the expected length.');
            let resultData = deleteTicketMessage(messageID, requestData.ticketID, userKey);
            assert.equal(resultData, 'Ticket deleted', `The request data is invalid or a different error has been thrown. ${typeof resultData === 'string' ? 'Error message: ' + resultData : ''}`);
            assert.equal(readAllTicketList(userKey).length, 0, 'Length of the returned array does not match the expected length.');
        });
    });
});