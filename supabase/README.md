# Connect ECE Nexus to Supabase

The portal uses Supabase Auth for email/password login and PostgreSQL row-level security for student submissions, faculty inboxes, and project messages. New student and faculty accounts enter an administrator approval queue.

## Set up the database

1. Open the ECE Nexus project in the Supabase Dashboard.
2. Open **SQL Editor**, choose **New query**, paste all of `setup.sql`, and click **Run** once.
3. In **Authentication → URL Configuration**, set the Site URL and add this Redirect URL:

   `https://24e55a0404.github.io/ECE-APP/`

4. In **Authentication → Providers**, keep **Email** enabled. People must use an email they can access and confirm that email before approval.

## Email delivery

The confirmation email goes to the address entered on the signup form. Supabase's default sender is for testing and only delivers to authorized project-team addresses. To deliver confirmations to students' and faculty members' addresses, configure a custom SMTP provider in **Authentication → SMTP Settings** before signup, then use **Resend confirmation email** on the portal if needed. Keep SMTP credentials in Supabase settings; never put them in this repository or browser code.

The portal does not email the administrator when an access request is created. The administrator reviews requests in **Access requests** after logging in. Sending separate admin or faculty notifications requires an email provider and a server-side function.

## Create the first department administrator

The administrator is the only account that can approve student and faculty requests. First create a normal account using the portal, then confirm that account's email. In SQL Editor, replace the address below with the department administrator's confirmed email and run both statements:

```sql
update public.profiles
set role = 'admin', approval_status = 'approved'
where email = 'admin@college.edu';

update public.access_requests
set status = 'approved', reviewed_at = now()
where user_id = (select id from public.profiles where email = 'admin@college.edu');
```

Then return to the portal, choose **Department administrator? Log in**, and use that account's own email and password. The new **Access requests** page lists requests with each person's name, email, role, and faculty domain. Select **Approve** or **Reject**. Approved users can log in with the same email and password they registered; they do not receive or share credentials with the administrator.

## Student and faculty access

On the portal, choose **Student** or **Faculty**, select the account request link, enter a name, email, and password, then submit the request. Faculty also choose their domain. They confirm their email and wait for department approval. Selecting Faculty at login does not grant faculty permissions by itself.

The project uses the public **Publishable key** in browser code. Never put a Supabase **Secret** or legacy `service_role` key in this repository. Project communication appears in the portal inbox; automatic external email alerts require a separate mail provider and server-side function.
