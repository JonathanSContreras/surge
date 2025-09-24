        # if down connect using dashed lines
        if state != "up":
            G.add_edge(SCANNER, ip)
        else:
            G.add_edge(SCANNER, ip)