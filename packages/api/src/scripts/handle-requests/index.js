const { sha256 } = require("../../helpers/dataEncryption");
const { addSupportTicketStatus, addSupportMessage, addSupportTicket,
    getTicketByID, deleteTicket, deleteTicketMessages, deleteTicketStatus,
    getTicketsByUserKey, getTicketStatusByTicketId, getTicketMessagesByTicketId,
    deleteMessageByRandomId, addAttachment, addSupportMessageStatus, getRandomId,
    deleteMessageStatus, deleteAttachments, deleteAttachmentsByMessageID, deleteMessageStatusByMessageID,
    getAttachmentByHashedId, getMessageStatusesByTicketId, getTeamMember, getAllTickets,
    getTicketStatusHistoryByTicketId, getLastThreeTicketMessageByTicketId } = require("../database/commands");

const MAXIMUM_MESSAGE_LENGTH = 12000

function createConversation(data, ticketID, userKey) {

    try {

        if (data.message.length > MAXIMUM_MESSAGE_LENGTH) {
            return 'Message is too long.'
        }

        addSupportTicket({
            userKey,
            ticketID,
            content: data.ticket
        })

        addSupportTicketStatus({
            hashedTicketID: sha256(ticketID),
            content: data.ticketStatus
        })

        const messageID = getRandomId();
        addSupportMessage({
            randomID: messageID,
            hashedTicketID: sha256(ticketID),
            content: data.message
        })

        addSupportMessageStatus({
            messageID,
            hashedTicketID: sha256(ticketID),
            content: data.messageStatus
        })

        data.attachments.forEach(el => {
            addAttachment({
                hashedAttachmentID: el.hash,
                messageID,
                hashedTicketID: sha256(ticketID),
                content: el.content
            })
        })

        return {
            msg: "Success",
            userKey: userKey,
            ticketId: ticketID
        }

    } catch (err) {
        return (err.name + ': ' + err.message);
    }
}

function deleteConversation(ticketID) {

    try {
        const ticket = getTicketByID(ticketID);
        if (!ticket) {
            return 'Ticket does not exist.';
        }
        const userKey = ticket.userKey;
        if (userKey != userKey && getTeamMember(userKey) === undefined) {
            return 'User is not authorized.';
        }
        deleteTicket(ticketID);
        const hashedTicketID = sha256(ticketID);
        deleteTicketMessages(hashedTicketID);
        deleteTicketStatus(hashedTicketID);
        deleteMessageStatus(hashedTicketID);
        deleteAttachments(hashedTicketID);

        return "Success";
    } catch (err) {
        return (err.name + ': ' + err.message);
    }
}

function deleteTicketMessage(messageId, ticketID) {

    try {
        const ticket = getTicketByID(ticketID);
        if (!ticket) {
            return 'Ticket does not exist.';
        }
        const userKey = ticket.userKey
        if (userKey != userKey && getTeamMember(userKey) === undefined) {
            return 'User is not authorized.';
        }
        const hashedTicketID = sha256(ticketID);
        if (getTicketMessagesByTicketId(hashedTicketID).length === 1) {
            deleteConversation(ticketID, userKey)
            return "Ticket deleted";
        } else {
            deleteMessageByRandomId(messageId);
            deleteAttachmentsByMessageID(messageId);
            deleteMessageStatusByMessageID(messageId);
        }

        return "Success";
    } catch (err) {
        return (err.name + ': ' + err.message)
    }
}

function readAllTicketList(userKey, HASH_TICKET_LIST, PAGE = 1, PAGE_SIZE = 8) {
    try {
        let tickets
        if (getTeamMember(userKey)) {
            tickets = getAllTickets(PAGE, PAGE_SIZE)
        } else {
            tickets = getTicketsByUserKey(userKey, PAGE, PAGE_SIZE);
        }
        const ticketsIDArray = tickets.map(el => el.ticketID)
        let result = []
        for (let i = 0; i < ticketsIDArray.length; i++) {
            const ticketID = ticketsIDArray[i];
            if (!ticketID) {
                continue
            }
            const hashedTicketID = sha256(ticketID);
            result.push({
                ticket: tickets[i],
                status: getTicketStatusByTicketId(hashedTicketID),
                messages: getLastThreeTicketMessageByTicketId(hashedTicketID),
                messageStatuses: getMessageStatusesByTicketId(hashedTicketID)
            })
        }
        if (sha256(JSON.stringify(result)) !== HASH_TICKET_LIST) {
            return result;
        } else {
            return ["No ticket changes."]
        }
    } catch (err) {
        return (err.name + ': ' + err.message)
    }
}

function changeTicketStatus(ticketID, content) {

    try {
        const ticket = getTicketByID(ticketID)
        if (!ticket) {
            return 'Ticket does not exist.';
        }
        const userKey = ticket.userKey
        if (userKey != userKey && getTeamMember(userKey) === undefined) {
            return 'User is not authorized.';
        }

        const hashedTicketID = sha256(ticketID);

        const ticketStatusData = {
            hashedTicketID,
            content
        }
        addSupportTicketStatus(ticketStatusData);

        return 'Success';

    } catch (err) {
        return (err.name + ': ' + err.message);
    }
}

function addTicketMessage(ticketID, userKey, data) {

    try {
        const ticket = getTicketByID(ticketID)
        if (!ticket) {
            return 'Ticket does not exist.';
        }
        if (ticket.userKey !== userKey && getTeamMember(userKey) === undefined) {
            return 'User not authorized.';
        }

        const messageID = getRandomId();

        addSupportMessage({
            randomID: messageID,
            hashedTicketID: sha256(ticketID),
            content: data.message
        })

        addSupportMessageStatus({
            messageID,
            hashedTicketID: sha256(ticketID),
            content: data.messageStatus
        })

        data.attachments.forEach(el => {
            addAttachment({
                hashedAttachmentID: el.hash,
                messageID,
                hashedTicketID: sha256(ticketID),
                content: el.content
            })
        })

        return "Success";

    } catch (err) {
        return (err.name + ': ' + err.message)
    }
}

function readSingleTicket(ticketID, userKey) {
    try {
        const ticket = getTicketByID(ticketID);
        if (!ticket) {
            return 'Ticket does not exist.';
        }
        if (ticket.userKey !== userKey && getTeamMember(userKey) === undefined) {
            return 'User not authorized to fetch current ticket.';
        }
        const result = {};
        const hashedTicketID = sha256(ticketID);
        result.ticket = ticket;
        result.status = getTicketStatusByTicketId(hashedTicketID);
        result.messages = getTicketMessagesByTicketId(hashedTicketID);
        result.messageStatuses = getMessageStatusesByTicketId(hashedTicketID);

        return result;
    } catch (err) {
        return (err.name + ': ' + err.message);
    }
}

function getAttachment(hashedAttachmentID) {
    try {
        const result = getAttachmentByHashedId(hashedAttachmentID);

        return result;
    } catch (err) {
        return (err.name + ': ' + err.message)
    }
}

function changeMessageStatus(content, messageID, ticketID, userKey) {

    try {
        const ticket = getTicketByID(ticketID)
        if (!ticket) {
            return 'Ticket does not exist.';
        }
        if (ticket.userKey !== userKey) {
            return 'User not authorized.';
        }

        const hashedTicketID = sha256(ticketID);

        const messageStatusData = {
            hashedTicketID,
            messageID,
            content
        }
        addSupportMessageStatus(messageStatusData);

        return 'Success';

    } catch (err) {
        return (err.name + ': ' + err.message);
    }
}

function getTicketStatusHistory(ticketID, userKey) {
    try {
        const ticket = getTicketByID(ticketID);
        if (!ticket) {
            return 'Ticket does not exist.';
        }
        if (ticket.userKey !== userKey && getTeamMember(userKey) === undefined) {
            return 'User not authorized to fetch current ticket.';
        }
        let result = [];
        const hashedTicketID = sha256(ticketID);
        result = getTicketStatusHistoryByTicketId(hashedTicketID);

        return result;
    } catch (err) {
        return (err.name + ': ' + err.message);
    }
}

module.exports = {
    createConversation,
    deleteConversation,
    readAllTicketList,
    changeTicketStatus,
    addTicketMessage,
    deleteTicketMessage,
    readSingleTicket,
    getAttachment,
    changeMessageStatus,
    getTicketStatusHistory
}