function get_subnet(a: addr): addr
{
    return remask_addr(a,0.0.0.0, 24);
}

function add_attack(tab: table[addr] of addr_set, orig_h: addr, resp_h: addr): count
{
    if(orig_h !in tab)
        tab[orig_h] = set();
    add tab[orig_h][get_subnet(resp_h)];
    return |tab[orig_h]|;
}
