DROP DATABASE cosign;
CREATE DATABASE cosign;
GRANT ALL PRIVILEGES ON cosign.* TO cosign@localhost IDENTIFIED BY 'cosign';

USE cosign;
CREATE TABLE login_cookies (
       login_cookie varchar(255) unique not null,
       ci_version integer not null,
       ci_ipaddr varchar(256) not null,
       ci_ipaddr_cur varchar(256) not null,
       ci_user varchar(130) not null,
       ci_ctime char(12) not null,
       ci_krbtkt varchar(255) not null,
       ci_state enum('logged out', 'active') not null default 'active',
       ci_itime integer not null,
       PRIMARY KEY (login_cookie)
       ) ENGINE=InnoDB;

CREATE TABLE service_cookies (
       service_cookie varchar(255) unique not null,
       login_cookie varchar(255) not null,
       PRIMARY KEY (service_cookie),
       FOREIGN KEY (login_cookie) REFERENCES login_cookies(login_cookie)
	ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE factor_timeouts (
       login_cookie varchar(255) not null,
       factor varchar(256) not null,
       timestamp integer not null,
       KEY(factor),
       KEY(login_cookie),
       KEY(login_cookie,factor),
       FOREIGN KEY (login_cookie) REFERENCES login_cookies(login_cookie)
	ON DELETE CASCADE
) ENGINE=InnoDB;
