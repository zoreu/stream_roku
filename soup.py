from html.parser import HTMLParser

class Node:
    def __init__(self, tag=None, attrs=None, parent=None, text=""):
        self.tag = tag
        self.attrs = attrs or {}
        self.children = []
        self.parent = parent
        self.text = text

    def __repr__(self):
        return f"<Node tag={self.tag} attrs={self.attrs} text={self.text[:15]!r}>"

    def get(self, attr, default=None):
        return self.attrs.get(attr, default)

    def find(self, tag=None, **attrs):
        for child in self.children:
            if (not tag or child.tag == tag) and MiniSoup._match(child, attrs):
                return child
            found = child.find(tag, **attrs)
            if found:
                return found
        return None

    def find_all(self, tag=None, **attrs):
        results = []
        for child in self.children:
            if (not tag or child.tag == tag) and MiniSoup._match(child, attrs):
                results.append(child)
            results.extend(child.find_all(tag, **attrs))
        return results

    def get_text(self):
        text = self.text
        for child in self.children:
            text += child.get_text()
        return text


class MiniSoup(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.root = Node(tag="document")
        self.current = self.root
        self.feed(html)

    @staticmethod
    def _match(node, attrs):
        for k, v in attrs.items():
            if k == "class":
                node_classes = node.attrs.get("class", "").split()
                if v not in node_classes:
                    return False
            elif node.attrs.get(k) != v:
                return False
        return True

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        new_node = Node(tag=tag, attrs=attrs_dict, parent=self.current)
        self.current.children.append(new_node)
        self.current = new_node

    def handle_endtag(self, tag):
        if self.current.parent:
            self.current = self.current.parent

    def handle_data(self, data):
        if data.strip():
            self.current.text += data.strip()

    def find(self, tag=None, **attrs):
        return self.root.find(tag, **attrs)

    def find_all(self, tag=None, **attrs):
        return self.root.find_all(tag, **attrs)
