import bcrypt from "bcryptjs";
import { connectDatabase, disconnectDatabase } from "../db/connect";
import { User } from "../models/User";

const DEMO_USERS = [
  { name: "Vaishnavi", email: "vaishnaviyedage19@gmail.com", password: "Demo@12345" },
  { name: "Saksham", email: "sakshamsingh3103@gmail.com", password: "Demo@12345" },
  { name: "Vinay", email: "vinaytodkar@gmail.com", password: "Demo@12345" },
];

async function main(): Promise<void> {
  await connectDatabase();
  for (const u of DEMO_USERS) {
    const passwordHash = await bcrypt.hash(u.password, 12);
    await User.findOneAndUpdate(
      { email: u.email },
      { name: u.name, email: u.email, passwordHash },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    );
    console.log(`Seeded ${u.email}`);
  }
  await disconnectDatabase();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
