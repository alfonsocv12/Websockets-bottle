from bottle_router import router

class Matcher(Router):

    def __init__():
        '''
        Constructor function
        '''
        pass

    def excect_route(self, websockets, path):
        '''
        Function dedicated to return the function that the path wants binding
        the websockets for fourther use of it
        '''
        route_tuple = self.match(path)
        route_tuple[0].callback(route_tuple[1])
