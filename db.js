// db.js (Kadam 35 Update - Star)
import { JSONFilePreset } from 'lowdb/node'

const defaultData = { 
  users: [
    /* { ... user data ... } */
  ],
  contacts: [
    /* { ... contact data ... } */
  ],
  groups: [
    /* { ... group data ... } */
  ],
  messages: [
    /* { 
        messageId: "...", 
        senderEmail: "...", 
        receiverGroupId: null, 
        text: "Hello",
        timestamp: 123456789,
        status: "sent",
        isDeleted: false,
        deletedBy: [],
        replyTo: null,
        isStarred: false // NAYA: Star flag
      }
    */
  ]
}

const db = await JSONFilePreset('db.json', defaultData)

export default db
