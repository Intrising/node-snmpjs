fs = require 'fs'
Lexer = require './lib/lexer'


printobj = (objs, ind='')->
  for o in objs
    if o.children
      console.log "#{ind}#{o.token}(#{o.len}):"
      printobj o.children, ind+'  '
    else
      console.log "#{ind}#{o.token}(#{o.len}): ", o.buf
 
scanbuf = (buf)->
  lexer = new Lexer()
  lexer.setInput buf
  robjs = []
  for i in [1..30]
    tokobj=lexer.simlex()
    break if tokobj.token is null
    if tokobj.token in ['SEQUENCE', 'CONTEXT_CONSTRUCTED_0']
      tokobj.children = scanbuf tokobj.buf
    robjs.push tokobj
  robjs


test = (buf)->
  objs= scanbuf buf
  #msgglobal = objs[0].children[2]
  #msgglobal.children = scanbuf1 msgglobal.buf
  printobj objs
fbuf = fs.readFileSync process.argv[2]
test(fbuf)

