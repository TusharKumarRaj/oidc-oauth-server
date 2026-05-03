import {
  uuid,
  pgTable,
  varchar,
  text,
  boolean,
  timestamp,
} from "drizzle-orm/pg-core";

export const usersTable = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),

  firstName: varchar("first_name", { length: 25 }),
  lastName: varchar("last_name", { length: 25 }),

  profileImageURL: text("profile_image_url"),

  email: varchar("email", { length: 322 }).notNull(),
  emailVerified: boolean("email_verified").default(false).notNull(),

  password: varchar("password", { length: 66 }),
  salt: text("salt"),

  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").$onUpdate(() => new Date()),
});

export const applicationsTable = pgTable("applications", {
  id: uuid("id").primaryKey().defaultRandom(),

  displayName: varchar("display_name", { length: 100 }).notNull(),
  applicationUrl: text("application_url").notNull(),
  redirectUri: text("redirect_uri").notNull(),

  clientId: varchar("client_id", { length: 64 }).notNull().unique(),
  clientSecret: varchar("client_secret", { length: 64 }).notNull(),

  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const authorizationCodesTable = pgTable("authorization_codes", {
  id: uuid("id").primaryKey().defaultRandom(),

  code: varchar("code", { length: 64 }).notNull().unique(),

  userId: uuid("user_id")
    .notNull()
    .references(() => usersTable.id),
  applicationId: uuid("application_id")
    .notNull()
    .references(() => applicationsTable.id),

  expiresAt: timestamp("expires_at").notNull(),
  used: boolean("used").default(false).notNull(),

  createdAt: timestamp("created_at").defaultNow().notNull(),
});
