/* admin */
ALTER SERVER EXT_FILECIPHER RESTART;

drop procedure PFC_HAS_AGENT_SESSION;
create procedure PFC_HAS_AGENT_SESSION perm '0000111110110'
in(
    agent_id        sb8
 )
out(
    has_agent_session     	ub1
);

