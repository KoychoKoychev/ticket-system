const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');

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
                    
                } else if (bodyData && bodyData.type === "CREATE_CONVERSATION") {

                } else if (bodyData && bodyData.type === "SEND_MESSAGE") {

                } else if (bodyData && bodyData.type === "CHANGE_STATUS") {

                } else if (bodyData && bodyData.type === "DELETE_CONVERSATION") {

                } else if (bodyData && bodyData.type === "DELETE_MESSAGE") {

                } else if (bodyData && bodyData.type === "READ_SINGLE_TICKET") {

                } else if (bodyData && bodyData.type === "GET_ATTACHMENT") {

                } else if (bodyData && bodyData.type === "CHANGE_MESSAGE_STATUS") {

                } else if (bodyData && bodyData.type === "REGISTER_STAFF_MEMBER") {

                } else if (bodyData && bodyData.type === "LOGIN_STAFF_MEMBER") {

                } else if (bodyData && bodyData.type === "GET_SUBJECT_MAPS") {

                } else if (bodyData && bodyData.type === "GET_TICKET_STATUS_HISTORY") {

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