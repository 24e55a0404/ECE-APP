# Connect ECE Nexus to Supabase

The site uses Supabase Auth for email/password accounts and PostgreSQL row-level security for private student submissions, faculty inboxes, and project messages.

## Set up the database

1. Open the ECE Nexus project in the Supabase Dashboard.
2. Open **SQL Editor**, choose **New query**, and paste the complete contents of `setup.sql`.
3. Select **Run** once. The script creates the profile, submission, and message tables, enables row-level security, and installs policies that limit each account to its own records and project participants.
4. In **Authentication → URL Configuration**, set the Site URL and add this Redirect URL:

   `https://24e55a0404.github.io/ECE-APP/`

5. In **Authentication → Providers**, leave **Email** enabled. Student registrations create student accounts; the user confirms their email before signing in.

## Enable faculty accounts

Faculty can choose **Faculty → Request faculty account access** on the portal and register their official email. New accounts are intentionally created as students until the department promotes them. After the faculty member confirms their email, run a query like this in SQL Editor, replacing the email and domain:

```sql
update public.profiles
set role = 'faculty', faculty_domain = 'VLSI Design'
where email = 'faculty.name@college.edu';
```

The faculty member can then choose **Faculty** and sign in. The role choice on the login page never grants faculty access by itself.

The project uses the public **Publishable key** in the browser. Never put a Supabase **Secret** or legacy `service_role` key in this repository. The submission conversation is stored in the portal inbox; automatic email alerts to faculty require a separate mail provider and server-side function.

