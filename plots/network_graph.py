import matplotlib.pyplot as plt
import networkx as nx

# df tiene filas (v, w, p)
def createGraph(df):

    G = nx.Graph()

    for index, row in df.iterrows():
        G.add_edge(row[0], row[1], weight=row[2])

    pos = nx.spring_layout(G)  # positions for all nodes

    # nodes
    nx.draw_networkx_nodes(G, pos, node_size=700)

    # edges
    nx.draw_networkx_edges(G, pos)

    # labels
    nx.draw_networkx_labels(G, pos, font_size=10)

    plt.axis("off")
    fig = plt.gcf()
    fig.set_size_inches(18.5, 10.5)
    fig.show()