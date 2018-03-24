def setup(**kwargs):
    print 'setup with %s' %kwargs

def cleanup():
    print 'cleanup'

def function1(arg1):
    print 'function1(%s)' %arg1

def function2(arg1, arg2=None):
    print 'function2(%s, %s)' %(arg1, arg2)

def function3(**kwargs):
    print 'function3(%s)' %kwargs

def do_something(arg1, arg2):
    print 'doing something with %s and %s' %(arg1, arg2)
