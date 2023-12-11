const Database = require('better-sqlite3')
const path = require('path');
const crypto = require('crypto');
const { toHex } = require('../../helpers/formatsTransform');
const { sha256 } = require('../../helpers/dataEncryption');

require('dotenv').config();

const db = new Database(path.resolve(process.env.DB_PATH) || path.resolve(__dirname, '..','..','..','data','tickets.db'));

function getRandomId() {
    const randomIDBuffer = crypto.getRandomValues(new Uint8Array(64))
    const randomID = toHex(randomIDBuffer);
    return randomID;
}

function getRandom32ByteID() {
    const randomIDBuffer = crypto.getRandomValues(new Uint8Array(32))
    const randomID = toHex(randomIDBuffer);
    return randomID
}

function getSalt() {
    const randomBuffer = crypto.getRandomValues(new Uint8Array(8))
    const salt = toHex(randomBuffer);
    return salt
}

function addSupportTicket(data) {
    const insertRowStm = db.prepare("INSERT INTO tickets VALUES (null, @randomID, @userKey, @ticketID, @content)");
    const randomID = getRandomId();
    insertRowStm.run({
        randomID,
        userKey: data.userKey,
        ticketID: data.ticketID,
        content: data.content
    });
}

function addSupportTicketStatus(data) {
    const insertRowStm = db.prepare("INSERT INTO ticketsStatus VALUES (null, @randomID, @hashedTicketID, @content)");
    const randomID = getRandomId();
    insertRowStm.run({
        randomID,
        hashedTicketID: data.hashedTicketID,
        content: data.content
    })
}

function addSupportMember(data) {
    const insertRowStm = db.prepare("INSERT INTO team VALUES (null, @teamID, @name, @picture, @role, @note, @username, @password, @salt)");
    insertRowStm.run({
        teamID: data.teamID,
        name: data.name,
        picture: data.picture,
        role: data.role,
        note: data.note,
        username: data.username,
        password: data.password,
        salt: data.salt
    })
}

function addSupportMessage(data) {
    const insertRowStm = db.prepare("INSERT INTO messages VALUES (null, @randomID, @hashedTicketID, @content)");
    insertRowStm.run({
        randomID: data.randomID,
        hashedTicketID: data.hashedTicketID,
        content: data.content
    })
}

function addSupportMessageStatus(data) {
    const insertRowStm = db.prepare("INSERT INTO messageStatus VALUES (null, @randomID, @messageID, @hashedTicketID, @content)");
    const randomID = getRandomId();
    insertRowStm.run({
        randomID,
        messageID: data.messageID,
        hashedTicketID: data.hashedTicketID,
        content: data.content // {created_at, status} info whether the message has been read or not
    })
}

function addAttachment(data) {
    const insertRowStm = db.prepare("INSERT INTO attachments VALUES (null, @hashedAttachmentID, @messageID, @hashedTicketID, @content)");
    insertRowStm.run({
        hashedAttachmentID: data.hashedAttachmentID,
        messageID: data.messageID,
        hashedTicketID: data.hashedTicketID,
        content: data.content //base64 of the file
    })
}

function getTeamMember(teamID) {
    const getTeamMemberStm = db.prepare(`SELECT * FROM team WHERE teamID='${teamID}'`);
    const teamMember = getTeamMemberStm.get()
    return teamMember;
}

function getTicketByID(ticketID) {
    const getTicketByIDStm = db.prepare(`SELECT userKey, ticketID, content FROM tickets WHERE ticketID='${ticketID}'`);
    const ticket = getTicketByIDStm.get();
    return ticket;
}

function deleteTicket(ticketID) {
    const deleteTicketStm = db.prepare(`DELETE FROM tickets WHERE ticketID='${ticketID}'`)
    deleteTicketStm.run()
}

function deleteTicketMessages(hashedTicketID) {
    const deleteMessageStm = db.prepare(`DELETE FROM messages WHERE hashedTicketID='${hashedTicketID}'`)
    deleteMessageStm.run()
}

function deleteTicketStatus(hashedTicketID) {
    const deleteTicketStatus = db.prepare(`DELETE FROM ticketsStatus WHERE hashedTicketID='${hashedTicketID}'`)
    deleteTicketStatus.run()
}

function deleteMessageStatus(hashedTicketID) {
    const deleteMessageStatus = db.prepare(`DELETE FROM messageStatus WHERE hashedTicketID='${hashedTicketID}'`)
    deleteMessageStatus.run()
}

function deleteAttachments(hashedTicketID) {
    const deleteAttachments = db.prepare(`DELETE FROM attachments WHERE hashedTicketID='${hashedTicketID}'`)
    deleteAttachments.run()
}

function deleteMessageStatusByMessageID(messageID) {
    const deleteMessageStatusStm = db.prepare(`DELETE FROM messageStatus WHERE messageID='${messageID}'`)
    deleteMessageStatusStm.run()
}

function deleteAttachmentsByMessageID(messageID) {
    const deleteAttachmentsStm = db.prepare(`DELETE FROM attachments WHERE messageID='${messageID}'`)
    deleteAttachmentsStm.run()
}

function getTicketsByUserKey(userKey, PAGE, PAGE_SIZE) {
    const getTicketsByUserKeyStm = db.prepare(`SELECT userKey, ticketID, content FROM tickets WHERE userKey='${userKey}' GROUP BY ticketID ORDER BY ID DESC LIMIT ${PAGE_SIZE} OFFSET ${(PAGE - 1) * PAGE_SIZE}`);
    const ticketsArr = getTicketsByUserKeyStm.all()
    return ticketsArr
}

function getTicketStatusByTicketId(hashedTicketID) {
    const getLatestTicketStatus = db.prepare(`SELECT content from ticketsStatus WHERE hashedTicketID='${hashedTicketID}' ORDER BY ID DESC LIMIT 1`);
    const ticketStatus = getLatestTicketStatus.get();
    return ticketStatus;
}

function getTicketStatusHistoryByTicketId(hashedTicketID) {
    const getTicketStatusHistory = db.prepare(`SELECT content from ticketsStatus WHERE hashedTicketID='${hashedTicketID}'`);
    const ticketStatusHistory = getTicketStatusHistory.all();
    return ticketStatusHistory;
}

function getTicketMessagesByTicketId(hashedTicketID) {
    const getTicketMessagesStm = db.prepare(`SELECT randomID, content FROM messages WHERE hashedTicketID='${hashedTicketID}' ORDER BY ID DESC`)
    const ticketMessages = getTicketMessagesStm.all();
    return ticketMessages
}

function getLastThreeTicketMessageByTicketId(hashedTicketID) {
    const getLastThreeTicketMessageStm = db.prepare(`SELECT randomID, content FROM messages WHERE hashedTicketID='${hashedTicketID}' ORDER BY ID DESC LIMIT 3`)
    const lastThreeTicketMessage = getLastThreeTicketMessageStm.all()
    return lastThreeTicketMessage
}

function getAttachmentByHashedId(hashedAttachmentID) {
    const getAttachmentStm = db.prepare(`SELECT messageID, content FROM attachments WHERE hashedAttachmentID='${hashedAttachmentID}'`)
    const attachment = getAttachmentStm.get()
    return attachment
}

function getMessageStatusesByTicketId(hashedTicketID) {
    const getMessageStatusesStm = db.prepare(`SELECT DISTINCT messageID, content, MAX(ID) AS ID FROM messageStatus WHERE hashedTicketID='${hashedTicketID}' GROUP BY messageID`);
    const statusesArr = getMessageStatusesStm.all()
    return statusesArr
}

function deleteMessageByRandomId(randomID) {
    const deleteMessageByRandomIdStm = db.prepare(`DELETE FROM messages WHERE randomID='${randomID}'`);
    deleteMessageByRandomIdStm.run();
}

function getSupportMemberData(username, password) {
    const getSupportMemberDataStm = db.prepare(`SELECT teamID, name, picture, role, password, salt FROM team WHERE username='${username}'`);
    const supportMemberData = getSupportMemberDataStm.get()
    if (!supportMemberData) return false
    const salt = supportMemberData.salt
    const hashedPass = supportMemberData.password
    if (sha256(password + salt) === hashedPass) {
        return supportMemberData
    } else {
        return false
    }
}

function checkIfUserExists(username) {
    const getSupportMemberDataStm = db.prepare(`SELECT * FROM team WHERE username='${username}'`);
    const supportMemberData = getSupportMemberDataStm.get()
    if (supportMemberData) return true
    else return false
}

function getAllTickets(PAGE, PAGE_SIZE) {
    const getTicketsStm = db.prepare(`SELECT userKey, ticketID, content FROM tickets GROUP BY ticketID LIMIT ${PAGE_SIZE} OFFSET ${(PAGE - 1) * PAGE_SIZE}`);
    const tickets = getTicketsStm.all();
    return tickets;
}

module.exports = {
    getRandomId,
    getSalt,
    addSupportTicket,
    addSupportTicketStatus,
    addSupportMember,
    checkIfUserExists,
    addSupportMessage,
    addSupportMessageStatus,
    addAttachment,
    getTeamMember,
    getRandom32ByteID,
    getTicketByID,
    getTicketsByUserKey,
    getTicketStatusByTicketId,
    getTicketMessagesByTicketId,
    getLastThreeTicketMessageByTicketId,
    getAttachmentByHashedId,
    getMessageStatusesByTicketId,
    getSupportMemberData: getSupportMemberData,
    getAllTickets,
    getTicketStatusHistoryByTicketId,
    deleteTicket,
    deleteTicketMessages,
    deleteTicketStatus,
    deleteMessageByRandomId,
    deleteMessageStatus,
    deleteAttachments,
    deleteMessageStatusByMessageID,
    deleteAttachmentsByMessageID
}