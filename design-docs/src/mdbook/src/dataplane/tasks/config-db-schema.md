# Configuration database schema

One of our biggest TODO items is to create an ER diagram for our configuration database.

To be clear, I am not asserting that we need to use an RDBMS in practice.
We just need an exacting spec for the relationships between our configuration data.

<figure title="ER Diagram for config db">

```plantuml
@startuml
skinparam linetype ortho
skinparam hyperlinkUnderline false

hide empty description
hide empty members
hide circle

entity Group {
  **id: PK<GroupId>**,
  name: String,
}

entity User {
  **id: PK<UserId>**,
  name: String,
}

entity GroupMembership {
  **id: PK<GroupMembershipId>**,
  user: FK<User>,
  group: FK<Group>,
}

entity Vpc {
  **id: PK<VpcId>**,
  name: String,
  vrf: u32,
  group: FK<Group>,
}

entity Discriminant {
  **id: PK<DiscriminantId>**,
  vni: Option<Vni>,
  vid: Option<Vid>,
  aci: Option<(Vid, Vni)>,
  ---
  <i>Note:</i>
  \t Exclusive: vni, vid, aci
  \t (only one non-null)
  
}

entity Interface {
  **id: PK<InterfaceId>**,
  meta: Unique<u32>,
  vpc: FK<Vpc>,
  name: String,
}

entity IpAddressAssignment<Ip> {
  **id: PK<AddressAssignmentId>**,
  vpc: FK<Vpc>,
  interface: FK<Interface>,
  cidr: (Ip, Subnet),
  ---
  -- prevent overlapping Ip assignments
  exclude using gist (
  \t vpc with =, cidr inet_ops with &&
  )
}

entity Peering {
  **id: PK<PeeringId>**,
  group: FK<Group>,
}

entity PeeringRelation {
  **id: PK<PeeringRelationId>**,
  type: <i>enum</i> (provider, consumer, peer, direct)
  peering: FK<Peering>,
  interface: FK<Interface>,
  ---
  <i>Note:</i>
  \t restrict to one provider 
  \t type per peering (needs gin index?)
}

Group ||--o{ Peering
Group ||--o{ Vpc
Group ||--o| GroupMembership
Interface ||--o{ IpAddressAssignment
Interface ||--|| Discriminant
Peering ||--o{ PeeringRelation
PeeringRelation }o--|| Interface
User ||--o| GroupMembership
Vpc ||--o{ Interface
Vpc ||-o{ IpAddressAssignment

@enduml
```

> We need to think about access controls and cardinality more.

</figure>
