function gogogo(cmd)
    xx(cmd)
end
function xx(cmd)
    os.execute("ls -l " .. cmd)
end
