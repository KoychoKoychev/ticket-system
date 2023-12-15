const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { readAllTicketList, createConversation, addTicketMessage, changeTicketStatus, 
    deleteConversation, deleteTicketMessage, readSingleTicket, getAttachment, 
    changeMessageStatus, getTicketStatusHistory } = require('../scripts/handle-requests');

function createWebServer(CERTS_DIR) {
    let server
    
    if(CERTS_DIR){
        const options = {
            cert: fs.readFileSync(path.resolve(CERTS_DIR, 'fullchain.pem')),
            key: fs.readFileSync(path.resolve(CERTS_DIR, 'privkey.pem'))
        }
        server = https.createServer(options, (req,res)=>{
            setupServer(req,res)
        })
    } else {
        server = http.createServer((req,res)=>{
            setupServer(req,res)
        })
    }

    function setupServer(req, res) {
        let pathname = url.parse(req.url, true).pathname;

        if (pathname === '/support' && req.method === 'POST') {
            let body = '';
            let bodyData = {};
            let resultData = {};
            let error = false;
            let reqEnd = false;
            req.on('data', (data) => {
                body += data;
            })
            req.on('error', () => {
                res.writeHead(503, {
                    'Content-Type': 'text/plain',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Origin, Content-Type'
                })
                return res.end();
            })
            req.on('close', () => {
                if (reqEnd === false) {
                    res.writeHead(503, {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Headers': 'Origin, Content-Type'
                    })
                    return res.end();
                }
            })
            req.on('end', () => {

                reqEnd = true
                res.writeHead(200, {
                    'Content-Type': 'text/plain',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Origin, Content-Type'
                })
                try {
                    bodyData = JSON.parse(body);
                    if (!bodyData) {
                        throw new Error();
                    }
                } catch (err) {
                    return res.end(JSON.stringify({ error: true, data: { msg: "Ivalid request data format." } }));
                }
                
                if (bodyData && bodyData.type === "READ_ALL_TICKET_LIST") {

                    if (!receivedData.page) receivedData.page = 1
                    if (!receivedData.pageSize) receivedData.pageSize = 8
                    if (!receivedData || !receivedData.userKey) {
                        error = true;
                        resultData = { msg: "No user key provided." };
                    } else {
                        resultData = readAllTicketList(receivedData.userKey, receivedData.hashData, receivedData.page,  receivedData.pageSize);
                    }
                } else if (bodyData && bodyData.type === "CREATE_CONVERSATION") {

                    let ticketID = receivedData.ticketID;
                    let userKey = receivedData.userKey;

                    resultData = createConversation(receivedData, ticketID, userKey);

                    if (resultData.msg === "Success") {
                        resultData = { msg: 'Ticket created successfully.', userKey: resultData.userKey, ticketId: resultData.ticketId }
                    }
                } else if (bodyData && bodyData.type === "SEND_MESSAGE") {

                    let ticketID = receivedData.ticketID;
                    let userKey = receivedData.userKey;
                    let messageData = {
                        "message": receivedData.message,
                        "attachments": receivedData.attachments,
                        "messageStatus": receivedData.messageStatus
                    }

                    resultData = addTicketMessage(ticketID, userKey, messageData);

                    if (resultData === "Success") {
                        resultData = { msg: 'Message sent successfully.' };
                    }
                } else if (bodyData && bodyData.type === "CHANGE_STATUS") {

                    let ticketID = receivedData.ticketID;
                    let ticketStatus = receivedData.content;
                    let userKey = receivedData.userKey;

                    resultData = changeTicketStatus(ticketID, ticketStatus, userKey);

                    if (resultData === "Success") {
                        resultData = { msg: 'Status changed successfully.' };
                    }

                } else if (bodyData && bodyData.type === "DELETE_CONVERSATION") {

                    let ticketID = receivedData.ticketID;

                    resultData = deleteConversation(ticketID);

                    if (resultData === "Success") {
                        resultData = { msg: 'Conversation deleted successfully.' };
                    }
            
                } else if (bodyData && bodyData.type === "DELETE_MESSAGE") {

                    let ticketID = receivedData.ticketID;
                    let messageID = receivedData.messageID;
                    resultData = deleteTicketMessage(messageID, ticketID);

                    if (resultData === "Success") {
                        resultData = { msg: 'Message deleted successfully.' };
                    }
                    if (resultData === "Ticket deleted") {
                        resultData = { msg: 'Ticket deleted successfully.' };
                    }

                } else if (bodyData && bodyData.type === "READ_SINGLE_TICKET") {

                    let ticketID = receivedData.ticketID;
                    let userKey = receivedData.userKey;

                    if (ticketID && userKey) {
                        resultData = readSingleTicket(ticketID, userKey);
                    } else {
                        resultData = { msg: 'Invalid request data.' };
                    }

                } else if (bodyData && bodyData.type === "GET_ATTACHMENT") {

                    let hashedAttachmentID = receivedData.hashedAttachmentID;

                    if (hashedAttachmentID) {
                        resultData = getAttachment(hashedAttachmentID);
                    } else {
                        resultData = { msg: 'Invalid request data.' };
                    }

                } else if (bodyData && bodyData.type === "CHANGE_MESSAGE_STATUS") {

                    const messageID = receivedData.messageID;
                    const messageStatus = receivedData.messageStatus;
                    const ticketID = receivedData.ticketID;
                    const userKey = receivedData.userKey

                    if (messageID && messageStatus) {
                        resultData = changeMessageStatus(messageStatus, messageID, ticketID, userKey);
                        if (resultData === "Success") {
                            resultData = { msg: "Messages status successfully changed." }
                        }
                    } else {
                        resultData = { msg: 'Invalid request data.' };
                    }

                } else if (bodyData && bodyData.type === "REGISTER_STAFF_MEMBER") {

                } else if (bodyData && bodyData.type === "LOGIN_STAFF_MEMBER") {

                } else if (bodyData && bodyData.type === "GET_TICKET_STATUS_HISTORY") {

                    let ticketID = receivedData.ticketID;
                    let userKey = receivedData.userKey;

                    if (ticketID && userKey) {
                        resultData = getTicketStatusHistory(ticketID,userKey)
                    } else {
                        resultData = { msg: 'Invalid request data.' };
                    }
                } else {
                    return res.end(JSON.stringify({ error: true, data: { msg: "Wrong request type." } }));
                }

                if (typeof resultData === 'string') {
                    error = true;
                    resultData = { msg: resultData };
                }
                return res.end(JSON.stringify({ error, data: resultData }));
            })
        } else {
            res.writeHead(503, {
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Origin, Content-Type'
            })
            return res.end();
        }
    }

    return server;
}

module.exports = { createWebServer }