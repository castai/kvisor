
-- Create tables.
create table if not exists unique_dns_domains
(
    domain String,
    total UInt64
)
    engine = SummingMergeTree()
order by (domain);

create table if not exists unique_dst_ips
(
    dst_ip IPv6,
    total UInt64
)
    engine = SummingMergeTree()
order by (dst_ip);

create table if not exists unique_binaries_paths
(
    file_path String,
    total UInt64
)
    engine = SummingMergeTree()
order by (file_path);

-- Create materialized views.
create materialized view unique_dns_domains_mv
            to unique_dns_domains as
select dns_question_domain as domain, count() as total
from events where name='dns'
group by dns_question_domain;

create materialized view unique_dst_ips_mv
            to unique_dst_ips as
select dst_ip, count() as total
from events where name='tcp_connect'
group by dst_ip;

create materialized view unique_binaries_paths_mv
            to unique_binaries_paths as
select file_path, count() as total
from events where name='exec'
group by file_path;

-- Examples
select * from unique_dns_domains order by total desc limit 10;
select * from unique_dst_ips order by total desc limit 10;
select * from unique_binaries_paths order by total desc limit 10;
