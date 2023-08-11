CREATE TABLE IF NOT EXISTS accounts (
    account_id INT NOT NULL AUTO_INCREMENT,
    school_email VARCHAR(30) UNIQUE,
    username VARCHAR(30) UNIQUE,
    hashed_pass VARCHAR(255),
    created_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP(),
    class VARCHAR(30) NOT NULL,
    PRIMARY KEY (account_id),
    UNIQUE (account_id, username, school_email));

CREATE TABLE IF NOT EXISTS verification_token (
	TOKEN VARCHAR(1000) NOT NULL ,
    account_id INT NOT NULL,
    timecreated DATETIME DEFAULT CURRENT_TIMESTAMP(),
	token_type VARCHAR(10) DEFAULT 'signup',
    used_boolen BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (account_id, timecreated, token_type)
    );

CREATE TABLE IF NOT EXISTS verify_as_educator_request (
	account_id INT NOT NULL,
    employee_id VARCHAR(20) NOT NULL,
    department VARCHAR(100) NOT NULL,
    request_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP(),
    PRIMARY KEY (account_id),
    FOREIGN KEY (account_id) REFERENCES accounts(account_id),
    UNIQUE (account_id, employee_id)
);

CREATE TABLE IF NOT EXISTS posts (
	post_id INT NOT NULL AUTO_INCREMENT,
	title VARCHAR(50) NOT NULL,
	body VARCHAR(1000),
    post_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP(),
	category VARCHAR(30),
	account_id INT NOT NULL,
    like_count INT DEFAULT 0,
    comment_count INT DEFAULT 0,
	PRIMARY KEY (post_id),
	FOREIGN KEY (account_id) REFERENCES accounts(account_id)
    );

CREATE TABLE IF NOT EXISTS likes (
	like_id INT NOT NULL AUTO_INCREMENT, 
    like_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP(), 
    post_id INT NOT NULL, 
    account_id INT NOT NULL, 
    PRIMARY KEY (like_id), 
    FOREIGN KEY (post_id) REFERENCES posts(post_id), 
    FOREIGN KEY (account_id) REFERENCES accounts(account_id)
    );

CREATE TABLE IF NOT EXISTS comments (
	comment_id INT NOT NULL AUTO_INCREMENT, 
    body VARCHAR(200) NOT NULL, 
    comment_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP(), 
    account_id INT NOT NULL, 
    post_id INT NOT NULL, 
    PRIMARY KEY (comment_id), 
    FOREIGN KEY (account_id) REFERENCES accounts(account_id), 
    FOREIGN KEY (post_id) REFERENCES posts(post_id)
    );

CREATE TABLE IF NOT EXISTS chat_session (chat_id INT NOT NULL AUTO_INCREMENT, established_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP(), PRIMARY KEY (chat_id));

CREATE TABLE IF NOT EXISTS messages (

	message_id INT NOT NULL AUTO_INCREMENT, 
    sent_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP(), 
    body VARCHAR(500), 
    account_id INT NOT NULL, 
    chat_id INT NOT NULL, 
    PRIMARY KEY (message_id), 
    FOREIGN KEY (account_id) REFERENCES accounts(account_id), 
    FOREIGN KEY (chat_id) REFERENCES chat_session(chat_id)
    );

CREATE TABLE IF NOT EXISTS direct_chat (
	chat_id INT NOT NULL AUTO_INCREMENT, 
    established_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP(), 
    destination_account_id INT NOT NULL, 
    PRIMARY KEY (chat_id), 
    FOREIGN KEY (destination_account_id) REFERENCES accounts(account_id)
    );

CREATE TABLE  IF NOT EXISTS group_chat (
	chat_id INT NOT NULL AUTO_INCREMENT, 
    established_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP(), 
    member_list VARCHAR(100), 
    PRIMARY KEY (chat_id)
    );

CREATE TABLE IF NOT EXISTS students (
	account_id INT NOT NULL PRIMARY KEY REFERENCES accounts(account_id),
    school VARCHAR(100), 
    course VARCHAR(100), 
    interest_selection VARCHAR(100)
    );

CREATE TABLE IF NOT EXISTS educators (
	account_id INT NOT NULL PRIMARY KEY REFERENCES accounts(account_id),  
    school VARCHAR(100), 
    department VARCHAR(100),
    interest_selection VARCHAR(100)
    );

CREATE TABLE IF NOT EXISTS administrators (
	account_id INT NOT NULL PRIMARY KEY REFERENCES accounts(account_id),
    privilege_level INT
    );

CREATE TABLE IF NOT EXISTS blocks (
	blocked_account_id INT NOT NULL, 
    blocker_account_id INT NOT NULL, 
    blocked_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP(), 
    PRIMARY KEY (blocked_account_id, blocker_account_id), 
    FOREIGN KEY (blocked_account_id) REFERENCES accounts(account_id), 
    FOREIGN KEY (blocker_account_id) REFERENCES accounts(account_id)
    );

CREATE TABLE IF NOT EXISTS follow_account (
	follower_id INT NOT NULL, 
    followee_id INT NOT NULL, 
	followed_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP(), 
    PRIMARY KEY (follower_id, followee_id), 
    FOREIGN KEY (follower_id) REFERENCES accounts(account_id), 
    FOREIGN KEY (followee_id) REFERENCES accounts(account_id)
    );

CREATE TABLE IF NOT EXISTS account_status (
	account_id INT NOT NULL, 
    failed_attempts INT, 
    ongoing_timer VARCHAR(20), 
    locked_status VARCHAR(20) NOT NULL DEFAULT 'unlocked', 
    PRIMARY KEY (account_id), 
    FOREIGN KEY (account_id) REFERENCES accounts(account_id)
    );

CREATE TABLE IF NOT EXISTS security_questions (
	account_id INT NOT NULL,
    qn1 VARCHAR(90),
    qn1_ans VARCHAR(90),
    qn2 VARCHAR(90),
    qn2_ans VARCHAR(90),
    PRIMARY KEY (account_id),
    FOREIGN KEY (account_id) REFERENCES accounts(account_id)
    );

CREATE TABLE IF NOT EXISTS report_post (
	report_id INT NOT NULL AUTO_INCREMENT,
	reporter_id INT NOT NULL,
    post_id INT NOT NULL,
    reason VARCHAR(300),
    report_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (report_id),
    FOREIGN KEY (reporter_id) REFERENCES accounts(account_id),
    FOREIGN KEY (post_id) REFERENCES posts(post_id)
	);