-- ECE Nexus account, project, and inbox schema for Supabase.
-- Run once in Supabase Dashboard > SQL Editor after reviewing the policies.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  display_name text not null default '',
  role text not null default 'student' check (role in ('student', 'faculty', 'admin')),
  faculty_domain text,
  created_at timestamptz not null default now()
);

create table if not exists public.project_submissions (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.profiles(id) on delete cascade,
  title text not null,
  domain text not null,
  team text not null,
  abstract text not null,
  faculty_pref_1 uuid not null references public.profiles(id),
  faculty_pref_2 uuid references public.profiles(id),
  faculty_pref_3 uuid references public.profiles(id),
  assigned_faculty_id uuid references public.profiles(id),
  status text not null default 'submitted' check (status in ('submitted', 'under_review', 'changes_requested', 'approved', 'active', 'rejected', 'completed')),
  deadline_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (faculty_pref_1 <> student_id),
  check (faculty_pref_2 is null or faculty_pref_2 <> student_id),
  check (faculty_pref_3 is null or faculty_pref_3 <> student_id),
  check (faculty_pref_2 is null or faculty_pref_2 <> faculty_pref_1),
  check (faculty_pref_3 is null or (faculty_pref_3 <> faculty_pref_1 and (faculty_pref_2 is null or faculty_pref_3 <> faculty_pref_2)))
);

create table if not exists public.project_messages (
  id uuid primary key default gen_random_uuid(),
  submission_id uuid not null references public.project_submissions(id) on delete cascade,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  recipient_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 10000),
  created_at timestamptz not null default now(),
  read_at timestamptz
);

create index if not exists project_submissions_student_idx on public.project_submissions(student_id, created_at desc);
create index if not exists project_submissions_pref1_idx on public.project_submissions(faculty_pref_1, created_at desc);
create index if not exists project_submissions_pref2_idx on public.project_submissions(faculty_pref_2, created_at desc);
create index if not exists project_submissions_pref3_idx on public.project_submissions(faculty_pref_3, created_at desc);
create index if not exists project_submissions_assigned_idx on public.project_submissions(assigned_faculty_id, created_at desc);
create index if not exists project_messages_recipient_idx on public.project_messages(recipient_id, created_at desc);
create index if not exists project_messages_submission_idx on public.project_messages(submission_id, created_at);

create or replace function public.handle_new_ece_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- Self-registration always creates a student profile. The department promotes faculty accounts separately.
  insert into public.profiles (id, email, display_name, role)
  values (
    new.id,
    new.email,
    coalesce(nullif(new.raw_user_meta_data ->> 'display_name', ''), split_part(new.email, '@', 1)),
    'student'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_ece on auth.users;
create trigger on_auth_user_created_ece
  after insert on auth.users
  for each row execute procedure public.handle_new_ece_user();

-- Backfill Auth accounts that already existed before this schema was installed.
insert into public.profiles (id, email, display_name, role)
select id, email, coalesce(nullif(raw_user_meta_data ->> 'display_name', ''), split_part(email, '@', 1)), 'student'
from auth.users
where email is not null
on conflict (id) do nothing;

create or replace function public.current_ece_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where id = auth.uid()
$$;

create or replace function public.can_access_ece_submission(target_id uuid, viewer_id uuid default auth.uid())
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.project_submissions s
    where s.id = target_id
      and (
        s.student_id = viewer_id
        or s.assigned_faculty_id = viewer_id
        or s.faculty_pref_1 = viewer_id
        or s.faculty_pref_2 = viewer_id
        or s.faculty_pref_3 = viewer_id
        or public.current_ece_role() = 'admin'
      )
  )
$$;

create or replace function public.guard_ece_submission_updates()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare viewer_role text := public.current_ece_role();
begin
  if viewer_role = 'student' then
    if old.student_id <> auth.uid()
      or new.student_id is distinct from old.student_id
      or new.status is distinct from old.status
      or new.assigned_faculty_id is distinct from old.assigned_faculty_id
      or new.deadline_at is distinct from old.deadline_at
      or new.created_at is distinct from old.created_at then
      raise exception 'Students can edit project details and ranked faculty preferences only.';
    end if;
  elsif viewer_role = 'faculty' then
    if new.student_id is distinct from old.student_id
      or new.title is distinct from old.title
      or new.domain is distinct from old.domain
      or new.team is distinct from old.team
      or new.abstract is distinct from old.abstract
      or new.faculty_pref_1 is distinct from old.faculty_pref_1
      or new.faculty_pref_2 is distinct from old.faculty_pref_2
      or new.faculty_pref_3 is distinct from old.faculty_pref_3
      or new.created_at is distinct from old.created_at then
      raise exception 'Faculty can update project status, guide assignment, and deadline only.';
    end if;
  elsif viewer_role is distinct from 'admin' then
    raise exception 'An active student or faculty account is required.';
  end if;
  new.updated_at := now();
  return new;
end;
$$;

create or replace function public.ensure_ece_faculty_preferences()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.assigned_faculty_id is not null
    and not exists (select 1 from public.profiles where id = new.assigned_faculty_id and role = 'faculty') then
    raise exception 'Assigned guide must be an active faculty account.';
  end if;
  if not exists (select 1 from public.profiles where id = new.faculty_pref_1 and role = 'faculty')
    or (new.faculty_pref_2 is not null and not exists (select 1 from public.profiles where id = new.faculty_pref_2 and role = 'faculty'))
    or (new.faculty_pref_3 is not null and not exists (select 1 from public.profiles where id = new.faculty_pref_3 and role = 'faculty')) then
    raise exception 'Faculty preferences must reference active faculty accounts.';
  end if;
  return new;
end;
$$;

drop trigger if exists ensure_ece_faculty_preferences on public.project_submissions;
create trigger ensure_ece_faculty_preferences
  before insert or update of faculty_pref_1, faculty_pref_2, faculty_pref_3, assigned_faculty_id on public.project_submissions
  for each row execute procedure public.ensure_ece_faculty_preferences();

drop trigger if exists guard_ece_submission_updates on public.project_submissions;
create trigger guard_ece_submission_updates
  before update on public.project_submissions
  for each row execute procedure public.guard_ece_submission_updates();

create or replace function public.guard_ece_message_participants()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.sender_id <> auth.uid()
    or not public.can_access_ece_submission(new.submission_id, new.sender_id)
    or not public.can_access_ece_submission(new.submission_id, new.recipient_id) then
    raise exception 'Only project participants can exchange messages.';
  end if;
  return new;
end;
$$;

drop trigger if exists guard_ece_message_participants on public.project_messages;
create trigger guard_ece_message_participants
  before insert on public.project_messages
  for each row execute procedure public.guard_ece_message_participants();

alter table public.profiles enable row level security;
alter table public.project_submissions enable row level security;
alter table public.project_messages enable row level security;

drop policy if exists "profiles_read_self_faculty_and_project_contacts" on public.profiles;
create policy "profiles_read_self_faculty_and_project_contacts"
  on public.profiles for select to authenticated
  using (
    id = auth.uid()
    or role = 'faculty'
    or public.current_ece_role() = 'admin'
    or exists (
      select 1 from public.project_submissions s
      where s.student_id = profiles.id
        and (s.assigned_faculty_id = auth.uid() or s.faculty_pref_1 = auth.uid() or s.faculty_pref_2 = auth.uid() or s.faculty_pref_3 = auth.uid())
    )
  );

drop policy if exists "student_create_own_submission" on public.project_submissions;
create policy "student_create_own_submission"
  on public.project_submissions for insert to authenticated
  with check (
    student_id = auth.uid()
    and public.current_ece_role() = 'student'
    and status = 'submitted'
    and assigned_faculty_id is null
    and deadline_at is null
  );

drop policy if exists "participants_read_submission" on public.project_submissions;
create policy "participants_read_submission"
  on public.project_submissions for select to authenticated
  using (
    student_id = auth.uid()
    or assigned_faculty_id = auth.uid()
    or faculty_pref_1 = auth.uid()
    or faculty_pref_2 = auth.uid()
    or faculty_pref_3 = auth.uid()
    or public.current_ece_role() = 'admin'
  );

drop policy if exists "student_edit_own_submission" on public.project_submissions;
create policy "student_edit_own_submission"
  on public.project_submissions for update to authenticated
  using (student_id = auth.uid() and public.current_ece_role() = 'student')
  with check (student_id = auth.uid() and public.current_ece_role() = 'student');

drop policy if exists "faculty_update_preferred_or_assigned_submission" on public.project_submissions;
create policy "faculty_update_preferred_or_assigned_submission"
  on public.project_submissions for update to authenticated
  using (
    public.current_ece_role() = 'faculty'
    and (assigned_faculty_id = auth.uid() or faculty_pref_1 = auth.uid() or faculty_pref_2 = auth.uid() or faculty_pref_3 = auth.uid())
  )
  with check (
    public.current_ece_role() = 'faculty'
    and (assigned_faculty_id = auth.uid() or faculty_pref_1 = auth.uid() or faculty_pref_2 = auth.uid() or faculty_pref_3 = auth.uid())
  );

drop policy if exists "admin_manage_all_submissions" on public.project_submissions;
create policy "admin_manage_all_submissions"
  on public.project_submissions for all to authenticated
  using (public.current_ece_role() = 'admin')
  with check (public.current_ece_role() = 'admin');

drop policy if exists "participants_read_project_messages" on public.project_messages;
create policy "participants_read_project_messages"
  on public.project_messages for select to authenticated
  using (sender_id = auth.uid() or recipient_id = auth.uid());

drop policy if exists "participants_send_project_messages" on public.project_messages;
create policy "participants_send_project_messages"
  on public.project_messages for insert to authenticated
  with check (sender_id = auth.uid());

drop policy if exists "recipient_mark_message_read" on public.project_messages;
create policy "recipient_mark_message_read"
  on public.project_messages for update to authenticated
  using (recipient_id = auth.uid())
  with check (recipient_id = auth.uid());

grant select on public.profiles to authenticated;
grant usage on schema public to authenticated;
grant update (display_name) on public.profiles to authenticated;
grant select, insert, update on public.project_submissions to authenticated;
grant select, insert on public.project_messages to authenticated;
grant update (read_at) on public.project_messages to authenticated;
grant execute on function public.current_ece_role() to authenticated;
revoke all on function public.current_ece_role() from public, anon;
revoke all on function public.can_access_ece_submission(uuid, uuid) from public, anon, authenticated;
revoke all on function public.handle_new_ece_user() from public, anon, authenticated;
revoke all on function public.guard_ece_submission_updates() from public, anon, authenticated;
revoke all on function public.ensure_ece_faculty_preferences() from public, anon, authenticated;
revoke all on function public.guard_ece_message_participants() from public, anon, authenticated;

-- Faculty accounts are not self-selected: create/sign up the faculty user, then promote it
-- from the SQL Editor by replacing the email below with that person's official account email:
-- update public.profiles set role = 'faculty', faculty_domain = 'Embedded Systems'
-- where email = 'faculty.name@college.edu';

-- Approval workflow: students and faculty can register, but neither can use the portal
-- until a department administrator reviews their request.
alter table public.profiles add column if not exists approval_status text not null default 'pending'
  check (approval_status in ('pending', 'approved', 'rejected'));

create table if not exists public.access_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references public.profiles(id) on delete cascade,
  requested_role text not null check (requested_role in ('student', 'faculty')),
  faculty_domain text,
  request_details text not null default '',
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by uuid references public.profiles(id)
);
insert into public.access_requests (user_id, requested_role, faculty_domain, request_details)
select id, case when role = 'faculty' then 'faculty' else 'student' end, faculty_domain, 'Existing account; review access'
from public.profiles where role in ('student', 'faculty')
on conflict (user_id) do nothing;
alter table public.access_requests enable row level security;

create or replace function public.handle_new_ece_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare requested text := case when new.raw_user_meta_data ->> 'requested_role' = 'faculty' then 'faculty' else 'student' end;
begin
  insert into public.profiles (id, email, display_name, role, faculty_domain, approval_status)
  values (new.id, new.email,
    coalesce(nullif(new.raw_user_meta_data ->> 'display_name', ''), split_part(new.email, '@', 1)),
    'student', nullif(new.raw_user_meta_data ->> 'faculty_domain', ''), 'pending')
  on conflict (id) do nothing;
  insert into public.access_requests (user_id, requested_role, faculty_domain, request_details)
  values (new.id, requested, nullif(new.raw_user_meta_data ->> 'faculty_domain', ''),
    coalesce(new.raw_user_meta_data ->> 'request_details', ''))
  on conflict (user_id) do nothing;
  return new;
end;
$$;

-- Existing profiles remain pending until explicitly approved below. The first admin
-- must be bootstrapped once in SQL Editor with their own verified account email.
create or replace function public.current_ece_role()
returns text language sql stable security definer set search_path = public as $$
  select case when approval_status = 'approved' then role else null end
  from public.profiles where id = auth.uid()
$$;

create or replace function public.review_ece_access_request(request_uuid uuid, decision text)
returns void language plpgsql security definer set search_path = public as $$
declare req public.access_requests%rowtype;
begin
  if public.current_ece_role() is distinct from 'admin' then raise exception 'Department administrator access is required.'; end if;
  if decision not in ('approved', 'rejected') then raise exception 'Decision must be approved or rejected.'; end if;
  select * into req from public.access_requests where id = request_uuid for update;
  if not found then raise exception 'Access request not found.'; end if;
  update public.access_requests set status = decision, reviewed_at = now(), reviewed_by = auth.uid() where id = request_uuid;
  update public.profiles set
    approval_status = decision,
    role = case when decision = 'approved' then req.requested_role else 'student' end,
    faculty_domain = case when decision = 'approved' and req.requested_role = 'faculty' then req.faculty_domain else null end
  where id = req.user_id;
end;
$$;
revoke all on function public.review_ece_access_request(uuid, text) from public, anon;
grant execute on function public.review_ece_access_request(uuid, text) to authenticated;
grant select on public.access_requests to authenticated;
drop policy if exists "access_request_self_or_admin_read" on public.access_requests;
create policy "access_request_self_or_admin_read" on public.access_requests for select to authenticated
  using (user_id = auth.uid() or public.current_ece_role() = 'admin');

drop policy if exists "profiles_read_self_faculty_and_project_contacts" on public.profiles;
create policy "profiles_read_self_faculty_and_project_contacts" on public.profiles for select to authenticated
  using (
    id = auth.uid()
    or (role = 'faculty' and approval_status = 'approved')
    or public.current_ece_role() = 'admin'
    or (approval_status = 'approved' and exists (
      select 1 from public.project_submissions s where s.student_id = profiles.id
        and (s.assigned_faculty_id = auth.uid() or s.faculty_pref_1 = auth.uid() or s.faculty_pref_2 = auth.uid() or s.faculty_pref_3 = auth.uid())
    ))
  );

-- One-time bootstrap after a department admin has created and verified an account:
-- update public.profiles set role='admin', approval_status='approved' where email='admin@college.edu';
-- update public.access_requests set status='approved', reviewed_at=now() where user_id=(select id from public.profiles where email='admin@college.edu');
-- This does not expose admin registration on the public portal.
