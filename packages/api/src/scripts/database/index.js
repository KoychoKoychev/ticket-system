const Database = require('better-sqlite3');

const db = new Database('data/tickets.db');

function createDb() {
    try{
        const createTicketsTbl = db.prepare("CREATE TABLE tickets(ID INTEGER PRIMARY KEY AUTOINCREMENT, randomID, userKey, ticketID, content)");
        const createTicketsStatusTbl = db.prepare("CREATE TABLE ticketsStatus(ID INTEGER PRIMARY KEY AUTOINCREMENT, randomID, hashedTicketID, content)");
        const createTeamTbl = db.prepare("CREATE TABLE team(ID INTEGER PRIMARY KEY AUTOINCREMENT, teamID, name, picture, role, note, username, password, salt)");
        const createMessagesTbl = db.prepare("CREATE TABLE messages(ID INTEGER PRIMARY KEY AUTOINCREMENT, randomID, hashedTicketID, content)");
        const createMessageStatusTbl = db.prepare("CREATE TABLE messageStatus(ID INTEGER PRIMARY KEY AUTOINCREMENT, randomID, messageID, hashedTicketID, content)");
        const createAttachmentsTbl = db.prepare("CREATE TABLE attachments(ID INTEGER PRIMARY KEY AUTOINCREMENT, hashedAttachmentID, messageID, hashedTicketID, content)");

        createTicketsTbl.run();
        createTicketsStatusTbl.run();
        createTeamTbl.run();
        createMessagesTbl.run();
        createMessageStatusTbl.run();
        createAttachmentsTbl.run();
    } catch(err) {
        console.log('DATABASE ALREADY EXISTS');
    }
}

createDb();