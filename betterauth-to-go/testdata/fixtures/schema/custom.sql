create table "users" ("id" text not null primary key, "name" text not null, "email_address" text not null unique, "email_verified" boolean not null, "image" text, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz default CURRENT_TIMESTAMP not null, "twoFactorEnabled" boolean, "isInstanceAdmin" boolean, "user_locale" text);

create table "sessions" ("id" text not null primary key, "expiresAt" timestamptz not null, "token" text not null unique, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz not null, "ipAddress" text, "userAgent" text, "user_id" text not null references "users" ("id") on delete cascade, "activeOrganizationId" text, "device" text);

create table "accounts" ("id" text not null primary key, "accountId" text not null, "providerId" text not null, "userId" text not null references "users" ("id") on delete cascade, "accessToken" text, "refreshToken" text, "idToken" text, "accessTokenExpiresAt" timestamptz, "refreshTokenExpiresAt" timestamptz, "scope" text, "password" text, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz not null);

create table "verifications" ("id" text not null primary key, "identifier" text not null, "value" text not null, "expiresAt" timestamptz not null, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz default CURRENT_TIMESTAMP not null);

create table "orgs" ("id" text not null primary key, "name" text not null, "slug" text not null unique, "logo" text, "createdAt" timestamptz not null, "metadata" text, "joinCode" text unique);

create table "member" ("id" text not null primary key, "org_id" text not null references "orgs" ("id") on delete cascade, "userId" text not null references "users" ("id") on delete cascade, "role" text not null, "createdAt" timestamptz not null);

create table "invitation" ("id" text not null primary key, "organizationId" text not null references "orgs" ("id") on delete cascade, "email" text not null, "role" text, "status" text not null, "expiresAt" timestamptz not null, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "inviterId" text not null references "users" ("id") on delete cascade);

create table "two_factors" ("id" text not null primary key, "secret" text not null, "backupCodes" text not null, "userId" text not null references "users" ("id") on delete cascade, "verified" boolean);

create table "passkey" ("id" text not null primary key, "name" text, "publicKey" text not null, "userId" text not null references "users" ("id") on delete cascade, "credentialID" text not null, "counter" integer not null, "deviceType" text not null, "backedUp" boolean not null, "transports" text, "createdAt" timestamptz, "aaguid" text);

create index "sessions_user_id_idx" on "sessions" ("user_id");

create index "accounts_userId_idx" on "accounts" ("userId");

create index "verifications_identifier_idx" on "verifications" ("identifier");

create unique index "orgs_slug_uidx" on "orgs" ("slug");

create index "member_org_id_idx" on "member" ("org_id");

create index "member_userId_idx" on "member" ("userId");

create index "invitation_organizationId_idx" on "invitation" ("organizationId");

create index "invitation_email_idx" on "invitation" ("email");

create index "two_factors_secret_idx" on "two_factors" ("secret");

create index "two_factors_userId_idx" on "two_factors" ("userId");

create index "passkey_userId_idx" on "passkey" ("userId");

create index "passkey_credentialID_idx" on "passkey" ("credentialID");