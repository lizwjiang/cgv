package org.g4.certificate.utilities;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.util.ArrayList;

/**
 * Utility class used to handle XML
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class XMLUtil {

    /**
     * Create a document which is used to append XML nodes
     *
     * @return
     */
    public static Document getNewDocument() {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.newDocument();
            return doc;
        } catch (ParserConfigurationException e) {
        }
        return null;
    }

    /**
     * Create an root element with the specified name
     *
     * @param doc
     * @param rootTagName
     * @return
     */
    public static Element createRootElement(Document doc, String rootTagName) {
        if (doc.getDocumentElement() == null) {
            Element root = doc.createElement(rootTagName);
            doc.appendChild(root);
            return root;
        }
        return doc.getDocumentElement();
    }

    /**
     * Create an element with the specified name
     *
     * @param parent
     * @param tagName
     * @return
     */
    public static Element createElement(Element parent, String tagName) {
        Document doc = parent.getOwnerDocument();
        Element child = doc.createElement(tagName);
        parent.appendChild(child);
        return child;
    }

    /**
     * create an child element with the specified name and value and append it in a parent element
     *
     * @param parent
     * @param tagName
     * @param value
     * @return
     */
    public static Element createElement(Element parent, String tagName, String value) {
        Document doc = parent.getOwnerDocument();
        Element child = doc.createElement(tagName);
        setElementValue(child, value);
        parent.appendChild(child);
        return child;
    }

    /**
     * output XML data in a file
     *
     * @param doc
     * @param path
     */
    public static void buildXmlFile(Document doc, String path) {
        TransformerFactory tfactory = TransformerFactory.newInstance();
        try {
            Transformer transformer = tfactory.newTransformer();
            DOMSource source = new DOMSource(doc);

            StreamResult result = new StreamResult(new File(path));
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("encoding", "UTF-8");
            transformer.transform(source, result);

        } catch (TransformerConfigurationException e) {
            //TODO
        } catch (TransformerException e) {

        }
    }

    /**
     * Get all child nodes of a parent node
     *
     * @param parent
     * @return
     */
    public static NodeList getNodeList(Element parent) {
        return parent.getChildNodes();
    }

    /**
     * Get the node set from parent node by the specified  name
     *
     * @param parent
     * @param name
     * @return
     */
    public static Element[] getElementsByName(Element parent, String name) {
        ArrayList resList = new ArrayList();
        NodeList nl = getNodeList(parent);
        for (int i = 0; i < nl.getLength(); i++) {
            Node nd = nl.item(i);
            if (nd.getNodeName().equals(name)) {
                resList.add(nd);
            }
        }
        Element[] res = new Element[resList.size()];
        for (int i = 0; i < resList.size(); i++) {
            res[0] = (Element) resList.get(i);
        }
        return res;
    }

    /**
     * Get the name of the element
     *
     * @param element
     * @return
     */
    public static String getElementName(Element element) {
        return element.getNodeName();
    }

    /**
     * Get the value of the specified element
     *
     * @param element
     * @return
     */
    public static String getElementValue(Element element) {
        NodeList nl = element.getChildNodes();
        for (int i = 0; i < nl.getLength(); i++) {
            if (nl.item(i).getNodeType() == Node.TEXT_NODE) {
                return element.getFirstChild().getNodeValue();
            }
        }

        return null;
    }

    /**
     * Get the value of the attribute of the element
     *
     * @param element
     * @param attr
     * @return
     */
    public static String getElementAttr(Element element, String attr) {
        return element.getAttribute(attr);
    }

    /**
     * Set the value of element
     *
     * @param element
     * @param val
     */
    public static void setElementValue(Element element, String val) {
        Node node = element.getOwnerDocument().createTextNode(val);
        NodeList nl = element.getChildNodes();
        for (int i = 0; i < nl.getLength(); i++) {
            Node nd = nl.item(i);
            if (nd.getNodeType() == Node.TEXT_NODE) {
                nd.setNodeValue(val);
                return;
            }
        }
        element.appendChild(node);
    }

    /**
     * Set the value of attribute
     *
     * @param element
     * @param attr
     * @param attrVal
     */
    public static void setElementAttr(Element element,
                                      String attr, String attrVal) {
        element.setAttribute(attr, attrVal);
    }

    /**
     * Add the child node to parent
     *
     * @param parent
     * @param child
     */
    public static void addElement(Element parent, Element child) {
        parent.appendChild(child);
    }

    /**
     * Add the element to the parent by the node name
     *
     * @param parent
     * @param tagName
     */
    public static void addElement(Element parent, String tagName) {
        Document doc = parent.getOwnerDocument();
        Element child = doc.createElement(tagName);
        parent.appendChild(child);
    }

    /**
     * add element to parent withe the specified value by the node name
     *
     * @param parent
     * @param tagName
     * @param text
     */
    public static void addElement(Element parent, String tagName, String text) {
        Document doc = parent.getOwnerDocument();
        Element child = doc.createElement(tagName);
        setElementValue(child, text);
        parent.appendChild(child);
    }

    /**
     * Remove the node from parent
     *
     * @param parent
     * @param tagName
     */
    public static void removeElement(Element parent, String tagName) {
        NodeList nl = parent.getChildNodes();
        for (int i = 0; i < nl.getLength(); i++) {
            Node nd = nl.item(i);
            if (nd.getNodeName().equals(tagName)) {
                parent.removeChild(nd);
            }
        }
    }

}
